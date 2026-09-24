Sund — Implementation Guide

Status: v0.6 (Draft) — companion to Sund-PRD.md

> New in 0.6: PRD 0.8's decision 16 — a device's storage ceiling is read by the
> device it caps and by nobody else. `quota_bytes` leaves the device list, a
> ceiling change pings only the affected device, and `GET /v1/me/quota` stays
> self-scoped.
>
> New in 0.5: scenario S7 rewritten for PRD 0.7's decision 15 — the management
> plane is account-scoped, the transport plane is not, and the cross-account send
> is now asserted positively rather than described. Implemented as
> `tests/test_tenant_isolation.py`.

> New in 0.4: the per-device storage quota of PRD 0.5 (decision 13) — the
> operator surface, the enforcement rule and the test coverage. Writing a ceiling
> stays out of the API; reading one does not, so the sketch gains
> `GET /v1/me/quota` and `quota_bytes` in the device list, and a ceiling change
> pings the account like any other administrative act.

> New in 0.3: the account administration model of PRD 0.4 — administration modes,
> the `admin`/`member` role, the role-granting invitation and the last-admin
> invariant — carried into the API sketch, the operator surface, both
> walkthroughs, the revocation sketch and the test scenarios. It closes the
> guide's own open item on who may revoke (see the end of this document). The
> mode is opt-in and this guide takes no position on which one a consumer should
> pick; PRD → Threat model → Administration carries the argument, including
> family-beacon's decision to stay flat. Everything else is unchanged from 0.2.
>
> New in 0.2: a Toolchain section, settling the build/test/run tooling for the
> first implementation step (July 2026). Two decisions of note: the SQLite driver
> is `modernc.org/sqlite` (pure Go, no cgo), and the system suite's `beaconsim`
> client mockup is written in Python rather than Go — deliberately a second
> language from the server, so it exercises the API as an independent client
> would rather than sharing the server implementer's assumptions. The unit suite
> stays pure Go.

This guide makes the PRD concrete: components, toolchain, API sketch, and two
end-to-end walkthroughs — onboarding the first device, and inviting a second one
— each step mapped to its Family Beacon equivalent. API shapes and JSON are
illustrative sketches; the PRD is normative where they disagree.

---

Components

One process, one file:

    sund            — static binary: HTTP API, queue engine, push dispatcher
    sund.db         — SQLite: accounts, devices, bundles, queues, messages

Optional, alongside (each its own product, integrated not embedded):

    ntfy            — self-hosted UnifiedPush distributor (Android wake-up)
    push gateway    — vendor-operated APNS relay (iOS wake-up; see PRD)
    reverse proxy   — TLS termination if not using sund's built-in listener

Operator surface (the Holm bar):

    sund serve --db sund.db --addr :5870
    sund admin account create --quota standard   → account id + first invitation
        [--admin-mode flat|managed]              → administration mode (PRD 0.4);
                                                   flat is the default
    sund admin device promote <device-id>        → recover a managed account that
                                                   lost its only admin; pings
                                                   every device, like any other
                                                   role change
    sund admin device quota <device-id> [<bytes>]→ per-device storage ceiling
                                                   (PRD 0.8); 0 removes it,
                                                   omitted shows it; a change
                                                   pings only the capped device
    cp sund.db backup/                            → backup
    mv sund-new sund && systemctl restart sund    → upgrade

---

Toolchain (build, test, run)

Two languages, deliberately: Go for everything that ships (the server) and for
the unit suite that runs against it in-process; Python for the system suite's
client mockup, kept a language apart from the server on purpose (see Testing).
Nothing here is optional tooling for "later" — this is what the first commit needs.

Go side (server + unit suite)

    go              1.25+ — the stdlib net/http pattern router ({id} path
                    params, no framework needed) only requires 1.22, but the
                    modernc.org/sqlite driver below raises the effective floor
                    to 1.25 (its go.mod directive; enforced by `go mod tidy`).
    modernc.org/sqlite   pure-Go SQLite driver, CGO_ENABLED=0. The one dependency
                    the server strictly needs. Chosen over mattn/go-sqlite3
                    (cgo) specifically so the one-binary bar (Components, above)
                    doesn't quietly require a C toolchain at build time or
                    complicate cross-compilation/static linking. Slightly slower
                    on writes than the cgo binding; irrelevant at this traffic
                    scale.
    crypto/ed25519  stdlib. The *only* crypto the server itself performs —
                    verifying request signatures (PRD: no server-side crypto
                    beyond that). Everything else (X3DH prekeys, payload AEAD)
                    is client-side and never lands in the server's go.mod.
    go test ./...   unit suite. No assertion library required; stdlib testing
                    is enough for the invariants it covers.
    golangci-lint   optional but recommended once the tree grows past a few
                    files; gofmt/go vet are free and already part of go.

System suite side (beaconsim, Python)

    python          3.12+
    uv              dependency management — single lockfile, no separate venv
                    ceremony; the closest Python equivalent to Go's own
                    simplicity.
    PyNaCl          Ed25519 (management-plane request signing), X25519
                    (X3DH-style prekey exchange), secretbox/box (payload AEAD).
                    Native NaCl primitives map directly onto the SimpleX-derived
                    queue design; a closer fit than the general-purpose
                    `cryptography` package.
    httpx           HTTP calls against the API.
    pytest          runner; each Testing → Scenario (S1-S10) is a test function.
                    A fixture builds the sund binary once per run (`go build`),
                    then starts/stops it per test against a temp SQLite file on
                    a random loopback port — same "per test, because startup is
                    milliseconds" design as the unit suite, just launched as a
                    subprocess instead of via go test.

CI and repo housekeeping

    Two per-commit jobs: `go test ./...` (unit suite) and a Python job that
    builds the binary then runs `pytest` (system suite) — both per the PRD's
    per-commit test strategy (decision 9). Only the Go unit suite additionally
    runs as the local pre-commit hook (`.githooks/pre-commit`, a plain shell
    script, no hook framework), since it alone is guaranteed fast enough (< 5 s)
    not to slow down commits. Git does not install hooks from a clone, so it is
    opt-in per working copy: `make hooks` points `core.hooksPath` at the
    directory. The hook is a convenience, never the gate — CI runs both suites on
    every push regardless, and `git commit --no-verify` skips it.

    Done: the repository is hosted publicly at github.com/mevoc/sund (MIT), so
    its first consumer — family-beacon, itself public — can pull both the source
    and the GHCR image from CI without credentials.

---

API sketch

Two planes, two authentication schemes (PRD: The two planes).

Management plane — requests signed with the device's Ed25519 identity key
(headers: device id, timestamp, nonce, signature over method+path+body):

    POST /v1/devices/register        enroll with one-time token (unsigned + token)
    GET  /v1/devices                 list account devices (incl. role)
    GET  /v1/me/quota                own ceiling + stored bytes, self-scoped
    POST /v1/devices/{id}/revoke     revoke a device        [admin; always self]
    POST /v1/devices/{id}/role       set a device's role    [admin; managed only]
    PUT  /v1/me/bundle               publish opaque key bundle (size-capped)
    GET  /v1/devices/{id}/bundle     fetch a peer's bundle
    PUT  /v1/me/push                 register push endpoint (UnifiedPush URL / token)
    POST /v1/invitations             mint one-time enrollment token  [admin]
    GET  /v1/invitations             list outstanding invitations
    POST /v1/invitations/{id}/revoke revoke one before use

The bracketed markers are the administration rule of PRD 0.4 (Devices → Roles and
administration). The admin check itself is not a mode switch in the handler:
every device in a `flat` account registers as an admin, so the same check yields
0.3's behaviour there. The mode is consulted in exactly one place — `/role`,
below. Three things sit beside the check:

- **Self-revocation is unconditional.** `POST /v1/devices/{id}/revoke` where the
  id is the caller's own always succeeds, for any role, including the account's
  last admin. Only revoking *another* device is gated.
- **The last-admin invariant is a refusal, not a permission** (409): the last
  non-revoked admin cannot be demoted, and cannot be revoked by a different
  device. Recovery when it leaves anyway is operator-side —
  `sund admin device promote <device-id>`.
- **`/role` is refused in a flat account** (409) rather than being a no-op: flat
  means every device is an admin by definition of the mode, so there is nothing
  to promote or demote, and the account cannot be walked into managed one
  demotion at a time. The mode itself has no endpoint at all.

Every administrative act — register, revoke, role change, invitation mint, and
a storage-ceiling change — pings the devices that can observe its effect: for the
first four that is every device in the account except the one that performed it,
not only the admins and never silently; for a ceiling change it is the single
device being capped, which is the only device that can read the result
(PRD 0.8, decision 16). `sund admin device promote` is performed by the operator
rather than by a device, so it has no actor to exclude and pings *every* device
(PRD → Devices). Three consequences a client implementer needs. Because a ceiling
is no longer in the device list, the refetch rule includes `GET /v1/me/quota`:
refetch the device list, the invitation list and the quota read on **any** ping,
or a ceiling change is undetectable. A
revocation pings its *target* as well, which means the ping goes out before the
target's push endpoint is cleared, in the same step — best-effort, so an
unreachable device learns from its next request instead. And since a ping carries
nothing, a woken client cannot tell which act fired it: refetch the device list
*and* the invitation list on any ping.

Transport plane — requests authenticated with per-queue keys only. No device
identity appears in these calls; that is the point:

    POST /v1/queues                  create queue → {recipient_id, sender_id}
    POST /v1/send/{sender_id}        append encrypted payload (+ttl)
    GET  /v1/recv/{recipient_id}     drain messages
    POST /v1/ack/{recipient_id}      acknowledge/delete
    POST /v1/retire/{recipient_id}   retire queue (rotation)

Queue security follows the SimpleX pattern: a queue is created "open"; the first
valid SEND binds the sender's per-queue key. The sender_id travels to the sender
out-of-band (invitation QR) or inside an already-encrypted message.

Server address everywhere below:  sund://beacon.family.example:5870#Fp7Kx…
(the fragment is the server certificate fingerprint; clients pin it — PRD:
Server address).

---

Walkthrough 1 — first device onboarding

Cast: the operator installs Sund; their own phone becomes the account's first
device. Family Beacon mapping in brackets: [FB: …].

Setup. Operator runs the binary and creates an account:

    $ sund admin account create
    account:    acc_9f2  (administration: flat)
    invitation: printed as QR + URL, one-time, short TTL, grants: admin
                carries: server address (with fingerprint) + enrollment token

(`flat` is the default and is PRD 0.3 behaviour: every device that enrolls
becomes an admin. `--admin-mode managed` is the opt-in alternative, under which
later enrollments default to `member`. The mode is fixed at provisioning — there
is no endpoint to change it. Which one a consumer picks is a product decision
with a real argument on each side: PRD → Threat model → Administration.)

[FB: a parent installs the Family Beacon server on the family NAS. The account is
the family. The CLI prints the "join our family" QR.]

    Operator CLI            Sund server              First phone (device A)
        │                        │                        │
        │ account create         │                        │
        │───────────────────────>│                        │
        │  QR {addr#fp, token}   │                        │
        │<───────────────────────│                        │
        │                        │      scan QR           │
        │                        │<───────────────────────│
        │                        │  1. generate Ed25519 keypair (on device)
        │                        │  2. pin server fingerprint from addr
        │                        │ POST /v1/devices/register {token, pubkey}
        │                        │<───────────────────────│
        │                        │  device_id dev_A       │
        │                        │───────────────────────>│
        │                        │ PUT /v1/me/bundle (opaque prekeys)
        │                        │<───────────────────────│
        │                        │ PUT /v1/me/push {ntfy endpoint}
        │                        │<───────────────────────│

Notes:
- The private key never leaves the phone; the server stores the public key only.
- The bundle is opaque client key material (X3DH-style prekeys) so *later*
  devices can establish sessions with A asynchronously. Sund stores, never reads.
- With one device there are no queues yet. A single-device account is valid but
  inert — Sund's unit of usefulness is the pair.
- Device A is an admin whichever administration mode the account uses: the first
  device of an account always is, because the last-admin invariant would
  otherwise be unsatisfiable. In a managed account A is, for now, the only device
  that can invite — and a managed account SHOULD gain a second admin before it
  gains members, so that losing A is not an operator-recovery event.

[FB: the parent's phone is now enrolled. The app shows "Family: 1 device". No
location is flowing anywhere — there is no one to flow to, and the server could
not read it if there were.]

---

Walkthrough 2 — inviting a second device

Cast: device A (enrolled) invites device B. [FB: the parent adds their child's
phone.] This flow solves the bootstrap problem — establishing the first secure
pairwise channel when none exists yet — with the SimpleX invitation pattern: the
QR itself carries a one-way queue address, and the first message through it
carries the reverse direction.

Step 1 — A prepares the invitation (management + transport plane):

    A: POST /v1/invitations {grants_role: "member"}
                                       → one-time enrollment token
    A: POST /v1/queues                 → Q1 {recipient_id: r1, sender_id: s1}
    A: displays QR containing:
       { server addr#fp, enrollment token, s1, A.pubkey, eph }
       where eph is an ephemeral secret generated by A, never sent to the server.

In a managed account this call is admin-only, and the role it grants is settled
here rather than after the fact — B is never briefly an admin and never briefly
un-roled. `grants_role` defaults to `member` in a managed account and is ignored
in a flat one, where every enrollment is an admin (0.3 behaviour). The mint pings
A's other devices, so an invitation cannot be minted unobserved.

[FB: parent taps "Add family member", hands the phone to the child or shows the
QR across the room. The QR is the entire trust ceremony — physical co-presence
is the authentication. Family Beacon runs flat accounts, so `grants_role` plays
no part there; see the Revocation section below.]

Step 2 — B enrolls (management plane):

    B: scan QR → pin fingerprint → generate Ed25519 keypair
    B: POST /v1/devices/register {token, pubkey}      → dev_B
    B: PUT /v1/me/bundle
    B: PUT /v1/me/push

Step 3 — B opens the reverse channel and answers through the forward one
(transport plane; the server cannot correlate these calls with dev_B):

    B: POST /v1/queues                 → Q2 {recipient_id: r2, sender_id: s2}
    B: POST /v1/send/s1  payload = ENC_eph{ s2, B.pubkey, session material }
       — first SEND binds B's per-queue sender key on Q1

Step 4 — A completes the pairing:

    A: (woken by push ping — contentless)
    A: GET /v1/recv/r1 → decrypts with eph, verifies B.pubkey against the
       device list (management plane), stores s2
    A: POST /v1/send/s2  payload = ENC_session{ confirmation }

Result: a duplex pair of blind queues — Q1 carries B→A, Q2 carries A→B. The
server knows A owns Q1 and B owns Q2 (quota + wake-up), but no record links
who sends into either. Clients rotate both queues periodically (PRD: Queues).

    A                       Sund                        B
    │ POST /invitations      │                          │
    │ POST /queues → r1,s1   │                          │
    │······ QR {addr#fp, token, s1, A.pub, eph} ·······>│  (off-server)
    │                        │  register, bundle, push  │
    │                        │<─────────────────────────│
    │                        │  POST /queues → r2,s2    │
    │                        │<─────────────────────────│
    │                        │  send s1: ENC_eph{s2,…}  │
    │    ping (contentless)  │<─────────────────────────│
    │<───────────────────────│                          │
    │ recv r1, verify        │                          │
    │ send s2: confirm       │                          │
    │───────────────────────>│─── ping ────────────────>│

[FB mapping of the same steps: the child's phone joins the family (Step 2 — it
appears in every family member's device list, satisfying the transparency rule:
no silent membership). Steps 3–4 are invisible plumbing; the app just shows
"Emma's phone added". From here, a location update is an encrypted payload on
the A→B queue; an SOS is the same message at high priority plus a wake-up ping;
arrival/departure events originate on the moving device via geofence wake
(PRD: Push architecture) and fan out over its per-pair queues.]

Fan-out note: with N devices, a full mesh is N·(N−1) unidirectional queues.
A family of five is 20 queues — trivial for the server, and each new device
repeats Walkthrough 2 once per existing peer (driven by the app, using the key
bundles for the asynchronous ones; only the *first* pairing needs the QR).

---

Revocation (the exit path, sketched)

    An admin, or the device itself: POST /v1/devices/{dev_lost}/revoke
    Server: identity key dead, its owned queues retired, push endpoint dropped.
    Peers: notified via device list change; drop the revoked device's queues,
    rotate their own, and re-key sessions client-side.

Who may issue it is settled in PRD 0.4 rather than left to the consumer, because
it is a server operation and only the server can refuse one:

- Flat account: any device may revoke any other. This is 0.3 behaviour and the
  default.
- Managed account: only an admin may revoke another device.
- Either mode: a device may always revoke *itself*, unconditionally, including
  the account's last admin. The one refusal is that the last admin cannot be
  revoked by a *different* device (409) — promote a second admin first.

Because revocation drops the target's undelivered messages along with its queues,
a client SHOULD treat it as a destructive action in its UI (confirm, name the
target device, say what is lost). There is no undo and Sund will not offer one:
an "unrevoke" would have to resurrect an identity key the peers have already been
told to stop trusting.

[FB: "Emma's phone was stolen" — a family device removes it; the family's
subsequent traffic is unreadable to the stolen phone, and Emma's own phone can
remove itself, which is what a wipe-on-loss flow uses. Family Beacon runs **flat**
accounts deliberately: `FamilyBeacon-Roster.md` (Removal) is normative that any
active device may remove any other and that no role confers authority, because
concentrating removal in an admin hands an abusive member the lock. Sund offers
managed mode; family-beacon declines it. See PRD → Threat model →
Administration — this is a live cross-repo disagreement, not a settled mapping.]

---

What Family Beacon adds on top (and Sund must not)

    Sund concept            Family Beacon meaning        Lives in
    ─────────────────────────────────────────────────────────────
    account                 the family                   Sund
    device                  a family member's phone      Sund
    invitation QR           "join our family"            Sund (ceremony: FB UI)
    message                 location / SOS / geofence    FB clients only
    queue pair              a family relationship        FB clients only
    key bundle              async pairing material       Sund stores, FB uses
    revocation              remove lost/left phone       Sund
    activity log            transparency ledger          FB clients only
    consent per feature     ethical line                 FB clients only

The right column is the Architecture Principle enforced in practice: the server
ships nothing in the middle column. If an implementation step seems to need the
server to know a payload is "a location", stop — it belongs client-side.

---

Testing

Two suites, both fast enough to run on every commit. No nightly tier — at this
size, a test that cannot run per-commit is a test that will not run.

Unit suite (target: < 5 s)

Plain `go test ./...` (the stack is locked: Go + SQLite, PRD decision 10); no
network, no disk beyond in-memory SQLite. Covers the invariants testable in isolation:

- request signature verification: good, bad, replayed nonce, stale timestamp
- invitation lifecycle: atomic single-use consumption, TTL expiry, revocation
- queue ID generation: recipient_id and sender_id unrelated, unpredictable
- sender-key binding on first SEND; rejection of a second binding attempt
- quota attribution to the owner account; enforcement at the cap
- per-device quota: a send that lands exactly on a ceiling succeeds and one byte
  more fails, at each level independently; 0 at either level means no ceiling
  there; stored bytes count ciphertext payload only (no envelope, no base64) and
  exclude expired-but-unpurged rows; when device ceilings over-commit the account
  ceiling the account ceiling still binds and refuses first; lowering a ceiling
  below current usage refuses further sends and deletes nothing; a device's usage
  counts only the queues it owns, so one device filling up leaves a peer with its
  own ceiling still able to receive
- the 507 body is byte-identical whichever ceiling tripped, so a sender cannot
  tell a device-level refusal from an account-level one (today's text, "account
  storage quota exceeded", is wrong for the device level and must change)
- a ceiling change pings the capped device and no other; `quota_bytes` does
  **not** appear in the device-list response, so a member cannot read a peer's
  ceiling; and `GET /v1/me/quota` returns the caller's own ceiling and stored
  bytes — a device can always tell being capped from being full
- the two leaks a later convenience would reintroduce, asserted rather than
  assumed: `/v1/me/quota` is self-scoped and its response carries no account
  *stored bytes* (a number readable by every member is a peer activity signal;
  the account ceiling is permitted), and the device-list response carries neither
  a ceiling nor usage for any device, the caller's own included — a peer's
  ceiling is not a member's to read (PRD 0.8, decision 16)
- message TTL expiry and deletion-unread
- revocation kills the identity key and owned queues in one step
- administration: the admin-only acts refused for a member in a managed account
  and allowed in a flat one; self-revocation allowed for every role including the
  last admin; the last-admin invariant refusing demotion and revocation-by-another
  while permitting self-revocation, and holding under concurrent revocations (the
  check and the write are one transaction); `/role` refused in a flat account;
  promote refused against a revoked device and in a flat account; an invitation
  granting the role it says it grants; no path that changes an account's
  administration mode after provisioning

System suite (target: < 30 s)

The unit under test is the real artifact: the compiled `sund` binary, started
against a temp SQLite file on a random loopback port — per test, because
startup is milliseconds. (A concrete payoff of the one-binary bar, worth
defending in CI: if startup gets slow enough to make per-test spawning hurt,
that is itself a regression.)

Driven by `beaconsim`, a headless Family Beacon client mockup (Python — see
Toolchain, above): a small library implementing the full client side — keypair
generation, fingerprint pinning, registration, key bundles, invitation parsing,
queue management and real E2E encryption of fake location/SOS payloads. It must
do real crypto: the server cannot decrypt anything, so only a true client can
assert end-to-end delivery. Kept a language apart from the server on purpose:
the test suite is Sund's first consumer, and an independent implementation is a
sharper check that the API is usable from outside Go than a same-language pair
would be — it can't quietly share the server implementer's assumptions about
encodings or field shapes. (Family Beacon's actual clients are Android/iOS/web
regardless, so beaconsim was never going to be literally reused code either
way — it's a reference pattern to port, and Python reads as close to that as Go
does.)

Scenario sequences (each an end-to-end script over the API):

S1 Onboarding + pairing — Walkthroughs 1 and 2 verbatim: first device, invite
   a second, duplex queue pair, exchange a location payload in both directions.
S2 Family mesh — five devices, 20 queues; one device fans out a location
   update; all four peers receive and decrypt it.
S3 Offline receiver — send while the "child's phone" is down; drain after it
   returns; a second message with a short TTL expires unread and is gone.
S4 Wake-up — a stub UnifiedPush distributor (an in-test HTTP handler) receives
   the ping; assert the ping body is empty: no payload, no queue ID, nothing.
   SOS is the same assertion plus the priority flag.
S5 Stolen phone — revoke a device: its signed requests fail, its owned queues
   are gone, peers see the device-list change (ping + refetch), rotate their
   queues and re-key; the revoked client's cached credentials open nothing.
S5b Managed account, authorization — a member device M1 tries to revoke a peer,
   mint an invitation and promote itself: all three refused, no device-list
   change, no ping. M1 can still revoke an outstanding invitation (fail-safe by
   design) and can revoke *itself*. An admin then revokes the second member M2:
   succeeds, and M2 is pinged before its push endpoint is cleared.
S5b2 Managed account, the last admin — the sole admin tries to demote itself and
   to be revoked by a member: both refused (409). It then revokes *itself*:
   succeeds, stranding the remaining members. `sund admin device promote`
   recovers the account and pings every device. Concurrency: two admins revoking
   each other at once leave exactly one non-revoked admin, never zero.
S5b3 Flat account, no roles to change — `/role` is refused (409) whoever calls
   it, and there is no request that changes the account's administration mode.
S5c No silent administration — a member device, woken only by the ordinary ping,
   refetches and sees the role change an admin made. Assert: every device in the
   account except the actor was pinged (not just the admins), role is present in
   the list every device reads, an invitation mint pings too, and the stored rows
   name no actor for any of the acts — there is no "X revoked Y" record to find.
S6 Invitation abuse — reuse a consumed token, use an expired one, use a revoked
   one: all fail closed; no device row is created.
S7 Tenant isolation — two accounts on one server. The management plane is
   isolated: cross-account device-list reads, bundle fetches and revokes all
   fail, and so does reading another account's queue. A cross-account *send*
   **succeeds**, and the scenario asserts that positively rather than leaving it
   untested — a send is authorized by the per-queue sender key alone, there is no
   tenancy fact to check, and a future change that quietly introduced one would
   be a blindness regression (PRD 0.7, decision 15). The scenario also covers the
   bearer-credential edges: an unbound queue is claimed by whoever first presents
   its sender ID with a key, and once bound a second key is refused.
S8 Blindness audit — the structural test. After every other scenario including
   S10, whose traffic is the bulkiest, open sund.db directly
   and assert: no table or column links a sender device to a queue; every
   stored payload is ciphertext; and the known plaintexts beaconsim sent
   (coordinates, "SOS") appear nowhere in the DB file or the server logs. The
   Architecture Principle as an executable regression test.
S9 Operator surface — with undelivered messages in queues: cp the DB (backup),
   kill the binary, restart against the copy, drain — everything survives.
   "Install. Deploy. Backup. Upgrade." is tested, not hoped.
S10 Quota bulkhead — two devices in one account, each given its own ceiling well
   under the account's. Because ceilings are operator-written, the scenario shells
   out to `sund admin device quota` against the same database the running binary
   holds open (SQLite WAL, one writer at a time — the CLI must open it the same
   way the server does, and the scenario is the place that proves the operator
   surface works on a live deployment rather than only at rest). Fill the first
   device's queues until sends to it are refused; assert the second device still
   receives, the account ceiling was never reached, and draining the first frees
   only its own headroom. Assert the refusal body does not say which ceiling
   tripped, that the ceiling change pinged only the device it capped, that the
   device list carries no ceiling for either device, and that
   `GET /v1/me/quota` on the capped device reports the ceiling it was given.
   Then clear that ceiling (0) and assert the device can again consume up to the
   account cap — 0.4 behaviour, unchanged underneath.

CI runs both suites on every commit; the unit suite additionally runs as a
pre-commit hook, installed per working copy with `make hooks` (Toolchain).
Exceeding the time targets above is treated as a regression.

Consumer contract tests (planned)

Both suites above test Sund against itself and against beaconsim — an
implementation this repo also owns. Neither can catch the failure that actually
matters to a consumer: a change here that is internally consistent, passes
S1–S10,
and still breaks the real client library on the other side.

The remedy is to run the consumer's own contract suite in this repo's CI: a job
that checks out github.com/mevoc/family-beacon at a pinned ref and runs its
tier-2 suite (enrollment, signing, queue lifecycle, revocation, quota, both
address forms of the pinning contract) against the binary just built here. Same
test code as the consumer runs; run from the other side, at the moment the
change is made rather than a week later. Design and tiers:
https://github.com/mevoc/family-beacon/blob/main/docs/FamilyBeacon-Testing.md

Family Beacon runs the mirror image of this — a scheduled canary against Sund
`main` — so the loop is closed from both ends. The two jobs are not redundant:
this one blocks a bad Sund change at the source, that one catches drift the
pinned ref is hiding.

Note that the test-vector dependency runs the same way. Sund's suites must track
Family Beacon's protocol test vectors, which are canonical in that repo under
`shared/protocol/testvectors/` and consumed here by checkout at a pinned ref — not
vendored. Two copies of a conformance corpus drift, and drift in the corpus hides
drift in the implementations.

Two prerequisites, both currently open:

- The GHCR package is private while this repo is. A consumer's CI that pulls
  `ghcr.io/mevoc/sund` needs a read-packages token or a public package.
- The image declares no `HEALTHCHECK`; `compose.yaml` supplies it. Moving
  `HEALTHCHECK ["CMD", "/sund", "health"]` into the Dockerfile would make the
  image self-describing everywhere — including GitHub Actions `services:`, whose
  `--health-cmd` is shell-form only and therefore cannot probe a distroless
  image at all — and would let compose files drop their healthcheck blocks.

---

Open items surfaced by this guide — resolved in PRD 0.3

1. Push ping fan-in: confirmed as the only transport→management linkage, now
   stated explicitly in the PRD's Threat model (decision #6).
2. Invitation TTLs and single-use semantics: specified — single-use, atomic
   consumption, default 15-minute TTL, revocable before use (decision #7).
3. Device-list change propagation: push a contentless ping AND require clients
   to refetch the device list before any new session (decision #8).

Resolved in PRD 0.4

4. "Which devices may revoke (any vs. admin-role)" — left here as an app-level
   policy for Family Beacon and a hypothetical capability flag in Sund. Settled
   the other way: it cannot be an app-level policy, because revocation is a
   server operation and a client-side rule restricting it binds only the device
   it restricts. It is now an optional per-account administration mode with an
   `admin`/`member` role (decision #12). What the mode does *not* settle is
   whether a family-shaped consumer should use it; family-beacon's roster spec
   argues it should not, and PRD 0.4 records that disagreement rather than
   closing it.
