# Sund — deviations from the PRD and implementation guide

Where the code, the guide or an issue departs from `Sund-PRD.md` (v0.5) or
`Sund-ImplementationGuide.md` (v0.4), it is recorded here at the time the departure
is made. Open entries are the agenda for the next spec revision; a revision closes
them by updating `Status`. Format and rules: `~/projects/CLAUDE.md`, *Design flow*.

This file was started on 2026-09-18 by auditing the code at commit `5843cdd` against
the PRD and guide, so the first entries are backfilled: the date is when they were
recorded, not when the choice was made. `Sund-Status.md` remains the as-built
reference; this file lists only the points where as-built and spec disagree.

Things that are **not** deviations and are not listed: features in V1 scope that are
simply not built yet (metrics endpoint, iOS push provider, consumer contract tests in
CI). Those are tracked in `Sund-Status.md` → "Not built yet".

---

## 2026-09-18 — Plain HTTP is the default; pinned TLS is opt-in

- Spec: `Sund-PRD.md` → Server address — "Pinned mode is the stronger model and
  remains Sund's self-host-first default"; decision 11 — "pinned mode remains the
  self-host-first default".
- Actual: `sund serve` listens on plain HTTP unless `--tls-dir` / `SUND_TLS_DIR` is
  given (`main.go`). The container image and `compose.yaml` serve plain HTTP and
  expect a reverse proxy (WebPKI mode). Pinned mode is fully implemented
  (`internal/tlsid`) but must be switched on.
- Why: the first deployment target (family-beacon) recommends WebPKI mode behind a
  proxy, and shipping HTTP-by-default kept the image and compose file trivial. The
  flip was deferred as a follow-up (`Sund-Status.md` → "Not built yet").
- Status: open. Either make pinned TLS the flagless default (auto-generating the CA
  in a data dir, and enabling it in the image) or change the PRD to say the
  *deployment recommendation* is pinned mode while the binary's default is the
  operator's choice.

## 2026-09-18 — Sender key is bound on first SEND, not supplied at queue creation

- Spec: `Sund-PRD.md` → Queues — "The server stores per-queue authentication keys
  supplied at creation; sender-side keys are per-queue, not device identity keys."
- Actual: a queue is created with `sender_key` NULL. The first `POST /v1/send/{id}`
  carries `Sund-Sender-Key`, which the server binds atomically; later sends verify
  against it and cannot rebind (`internal/store/queue.go`, `BindSenderKey`).
- Why: the recipient mints the queue and hands the sender ID out of band; it does not
  know the sender's per-queue key at creation time, so "supplied at creation" is not
  implementable without the recipient also choosing the sender's key. The guide
  (API sketch → "Queue security follows the SimpleX pattern") already describes
  first-SEND binding, and the PRD declares itself normative where they disagree.
- Status: open. Fold the guide's wording into the PRD's Queues section. Note the
  consequence for the threat model: an open queue can be claimed by whoever first
  presents its sender ID, so the sender ID is a bearer secret until bound.

## 2026-09-18 — Wake-up pings carry a priority hint

- Spec: `Sund-PRD.md` → Push wake-up — "A ping carries nothing — no payload, no queue
  ID. It only tells a device 'check in'"; Push architecture — "Pings are payload-free
  by design (no content, no queue IDs — only 'check in')."
- Actual: a send may set `"priority": true`, which the server forwards to the pinger
  as an opaque high/normal flag; the UnifiedPush provider sends it as an ntfy
  `Priority: high` header (`internal/server/transport.go`, `internal/push`). The
  body is still empty and no queue ID travels.
- Why: an SOS must wake an Android device through Doze, which needs a high-priority
  push. The guide's scenario S4 already tests "the priority flag"; the PRD does not
  mention it.
- Status: open. The PRD should state the flag and add it to the residual metadata
  list: the host, the UnifiedPush distributor and (on iOS) the gateway and Apple learn
  which wake-ups are urgent, which in a family-beacon deployment means they can tell
  an SOS from a location update by timing plus priority.

## 2026-09-18 — The schema has columns the PRD's "whole" data model does not

- Spec: `Sund-PRD.md` → Data model (the whole of it) — the seven tables and their
  columns; Principles — "What the server must store, it stores briefly (TTL) and
  legibly — documented here, auditable in the schema."
- Actual (`internal/store/store.go`): `accounts.quota_bytes`; `invitations.id` and
  `invitations.revoked`; `messages.seq`, `messages.id` and `messages.expires`
  (an absolute timestamp) where the PRD lists `ttl`. Nothing links a sender device to
  a queue, so the blindness claim is unaffected.
- Why: `quota_bytes` came with the storage-quota commit (0 = unlimited so upgrades do
  not cap old accounts); `invitations.id`/`revoked` implement decision 7's listable and
  revocable invitations, which the PRD's table row forgot; `seq` gives a stable
  delivery order at second-precision timestamps; `expires` is what the purge query
  needs.
- Status: folded into `Sund-PRD.md` v0.5 — the Data model table now lists
  `accounts.quota_bytes`, `invitations.id`/`revoked` and `messages.seq`/`id`/
  `expires`, with a note on what each is for, so the "auditable in the schema"
  promise is literally true again. The `messages.status` half of this entry is a
  product question rather than a documentation fix and is carried on as its own
  entry below.

## 2026-09-18 — Expired messages are purged lazily, on the next drain

- Spec: `Sund-PRD.md` → Messages — "expired messages are deleted unread";
  Principles — "it stores briefly (TTL)".
- Actual: `DrainMessages` deletes expired rows of *that queue* before returning live
  ones (`internal/store/queue.go`). There is no background sweeper. A queue whose
  owner never drains again keeps its expired ciphertext until the queue is retired
  or the owner is revoked. Expired rows do not count against quota.
- Why: per-queue lazy purge needs no timer and is correct from the client's point
  of view (an expired message is never delivered). `Sund-Status.md` states the
  behaviour.
- Status: open. Either add a periodic sweep (a few lines with a ticker) so the
  "stores briefly" promise holds for abandoned queues too, or qualify the PRD.

## 2026-09-18 — Guide: "who may revoke" is not a capability flag in Sund

- Spec: `Sund-ImplementationGuide.md` → Revocation — "Which devices may revoke (any
  vs. admin-role) is an app-level policy in FB, a capability flag in Sund."
- Actual: any non-revoked device in the account may revoke any other
  (`internal/server/devices.go`); `devices.capabilities` is stored opaquely and never
  read by the server. This matches the PRD (Threat model → Trust boundary — "any
  device may revoke another") and the Architecture Principle.
- Why: a server-enforced revoke permission would be application policy, which the
  PRD keeps out of Sund.
- Status: folded into `Sund-PRD.md` v0.4 and `Sund-ImplementationGuide.md` v0.3
  (PR #4) — but note that the *reasoning* above was overturned, not confirmed. A
  revoke permission is not application policy: revocation is a server operation,
  so a client-side rule restricting it binds only the device it restricts.
  Decision 12 makes it an optional per-account administration mode with an
  `admin`/`member` role, and the guide sentence is rewritten rather than deleted.
  The as-built behaviour is unchanged and is now named: it is PRD 0.4's `flat`
  mode, which stays the default.

## 2026-09-18 — Guide: no local pre-commit hook exists

- Spec: `Sund-ImplementationGuide.md` → Toolchain → CI — "Only the Go unit suite
  additionally runs as the local pre-commit hook (a plain script, no hook
  framework)"; Testing — "the unit suite additionally runs as a pre-commit hook".
- Actual: no hook script in the repo, no `core.hooksPath`, nothing in `Makefile`.
  Both suites run in GitHub Actions on every push and PR (`.github/workflows/`).
- Why: never set up; CI covers the gate.
- Status: open. Either add the script (and a `make hooks` target to install it) or
  remove the sentence from the guide.

## 2026-09-21 — `messages.status` is stored but never changes

- Spec: `Sund-PRD.md` → Messages — "Send (by sender ID), receive/ack (by recipient
  ID), per-message TTL, delivery status."
- Actual: `messages.status` is written as `'stored'` at append and never updated
  (`internal/store/queue.go`); an ack deletes the row rather than marking it, and
  an expired message is purged on the next drain. So there is exactly one status,
  and "delivery status" describes no behaviour a client can observe.
- Why: ack-deletes is the right default for a blind relay — keeping delivered rows
  around to carry a status would mean storing more, for longer, to no one's
  benefit. The column predates the decision and was never removed.
- Status: open, and split out of the 2026-09-18 data-model entry when the rest of
  it was folded into PRD 0.5. Either define the statuses a client may see and what
  transitions them (which means keeping rows past ack — weigh against
  "stores briefly"), or drop "delivery status" from the PRD and the column with
  it. Leaning drop: a recipient learns delivery by draining, and a sender learns
  nothing by design.

## 2026-09-20 — Sends into another account's queue are not refused

- Spec: `Sund-PRD.md` → Non-goals — "No cross-account or federated messaging in V1";
  `Sund-ImplementationGuide.md` → S7 — "Tenant isolation — two accounts on one server:
  cross-account queue reads, sends, bundle fetches and device-list reads all fail."
- Actual: `POST /v1/send/{sender_id}` authenticates with the per-queue sender key alone
  (`internal/server/transport.go`); no account is consulted. A holder of a sender
  credential can append to a queue owned by any account, and the server cannot tell
  which account — if any — they belong to. The isolation tests cover the management
  plane only (`internal/store/store_test.go` → `TestCrossAccountIsolation` for the
  device list, `bundles_test.go`, `revoke_test.go`, `tests/test_devices.py`); no test
  exercises a cross-account send.
- Why: the transport plane is deliberately pseudonymous. A send carries no device id,
  and no column links a sender to a queue, so the server would have to record the
  sender↔account link that the blindness guarantee (S8) exists to avoid. In that sense
  the code is right and the two spec sentences are the ones out of step: the isolation
  Sund actually offers is on the management plane and on the recipient side of a queue.
  `Sund-Status.md` → Multi-tenancy ("cross-account reads/sends/revokes fail") reads as
  the spec does and needs the same scoping.
- Status: open. Surfaced by `../postiljon` PRD v0.3 §7.1 and `../brygga` PRD v0.2
  BIND-1, which both depend on the current behaviour: Postiljon and Brygga are devices
  in separate accounts so that neither can revoke the other's queues, and publishers
  hold a per-queue sender credential while belonging to no account at all. Two ways to
  close it:
  (a) scope the PRD non-goal, S7 and `Sund-Status.md` to the management plane and the
  recipient side, and add a system test that a cross-account *read* fails while a send
  succeeds — recommended, since it documents what the design already guarantees; or
  (b) enforce per-account sends, which reintroduces the sender↔account link, contradicts
  S8, and would force Postiljon and Brygga to share one account. André decides.
