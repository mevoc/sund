Sund — Implementation Guide

Status: v0.2 (Draft) — companion to Sund-PRD.md

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
    pytest          runner; each Testing → Scenario (S1-S9) is a test function.
                    A fixture builds the sund binary once per run (`go build`),
                    then starts/stops it per test against a temp SQLite file on
                    a random loopback port — same "per test, because startup is
                    milliseconds" design as the unit suite, just launched as a
                    subprocess instead of via go test.

CI and repo housekeeping

    Two per-commit jobs: `go test ./...` (unit suite) and a Python job that
    builds the binary then runs `pytest` (system suite) — both per the PRD's
    per-commit test strategy (decision 9). Only the Go unit suite additionally
    runs as the local pre-commit hook (a plain script, no hook framework), since
    it alone is guaranteed fast enough (< 5 s) not to slow down commits.

    No git repository exists in this directory yet. `git init`, plus deciding on
    hosting (a private GitHub repo, matching the pattern in Skerry's CLAUDE.md,
    is the natural default absent a reason otherwise), is itself the first step
    before any of the above.

---

API sketch

Two planes, two authentication schemes (PRD: The two planes).

Management plane — requests signed with the device's Ed25519 identity key
(headers: device id, timestamp, nonce, signature over method+path+body):

    POST /v1/devices/register        enroll with one-time token (unsigned + token)
    GET  /v1/devices                 list account devices
    POST /v1/devices/{id}/revoke     revoke a device
    PUT  /v1/me/bundle               publish opaque key bundle (size-capped)
    GET  /v1/devices/{id}/bundle     fetch a peer's bundle
    PUT  /v1/me/push                 register push endpoint (UnifiedPush URL / token)
    POST /v1/invitations             mint one-time enrollment token

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
    account:    acc_9f2
    invitation: printed as QR + URL, one-time, short TTL
                carries: server address (with fingerprint) + enrollment token

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

    A: POST /v1/invitations            → one-time enrollment token
    A: POST /v1/queues                 → Q1 {recipient_id: r1, sender_id: s1}
    A: displays QR containing:
       { server addr#fp, enrollment token, s1, A.pubkey, eph }
       where eph is an ephemeral secret generated by A, never sent to the server.

[FB: parent taps "Add family member", hands the phone to the child or shows the
QR across the room. The QR is the entire trust ceremony — physical co-presence
is the authentication.]

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

    Any authorized device: POST /v1/devices/{dev_lost}/revoke
    Server: identity key dead, its owned queues retired, push endpoint dropped.
    Peers: notified via device list change; drop the revoked device's queues,
    rotate their own, and re-key sessions client-side.

[FB: "Emma's phone was stolen" — any parent device removes it; the family's
subsequent traffic is unreadable to the stolen phone. Which devices may revoke
(any vs. admin-role) is an app-level policy in FB, a capability flag in Sund.]

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
- message TTL expiry and deletion-unread
- revocation kills the identity key and owned queues in one step

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
S6 Invitation abuse — reuse a consumed token, use an expired one, use a revoked
   one: all fail closed; no device row is created.
S7 Tenant isolation — two accounts on one server: cross-account queue reads,
   sends, bundle fetches and device-list reads all fail.
S8 Blindness audit — the structural test. After S1–S7, open sund.db directly
   and assert: no table or column links a sender device to a queue; every
   stored payload is ciphertext; and the known plaintexts beaconsim sent
   (coordinates, "SOS") appear nowhere in the DB file or the server logs. The
   Architecture Principle as an executable regression test.
S9 Operator surface — with undelivered messages in queues: cp the DB (backup),
   kill the binary, restart against the copy, drain — everything survives.
   "Install. Deploy. Backup. Upgrade." is tested, not hoped.

CI runs both suites on every commit; the unit suite additionally runs as a
pre-commit hook. Exceeding the time targets above is treated as a regression.

Consumer contract tests (planned)

Both suites above test Sund against itself and against beaconsim — an
implementation this repo also owns. Neither can catch the failure that actually
matters to a consumer: a change here that is internally consistent, passes S1–S9,
and still breaks the real client library on the other side.

The remedy is to run the consumer's own contract suite in this repo's CI: a job
that checks out `../family-beacon` at a pinned ref and runs its tier-2 suite
(enrollment, signing, queue lifecycle, revocation, quota, both address forms of
the pinning contract) against the binary just built here. Same test code as the
consumer runs; run from the other side, at the moment the change is made rather
than a week later. Design and tiers:
`../../family-beacon/docs/FamilyBeacon-Testing.md`.

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
