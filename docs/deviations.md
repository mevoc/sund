# Sund — deviations from the PRD and implementation guide

Where the code, the guide or an issue departs from `Sund-PRD.md` (v0.3) or
`Sund-ImplementationGuide.md` (v0.2), it is recorded here at the time the departure
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
- Status: open. Update the PRD table so the "auditable in the schema" promise stays
  literally true. Related: `messages.status` exists but is never updated from
  `'stored'` (ack deletes the row), so the PRD's "delivery status" is not a feature;
  either drop the phrase or define what statuses exist.

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
- Status: open. Guide fix only: drop "a capability flag in Sund".

## 2026-09-18 — Guide: no local pre-commit hook exists

- Spec: `Sund-ImplementationGuide.md` → Toolchain → CI — "Only the Go unit suite
  additionally runs as the local pre-commit hook (a plain script, no hook
  framework)"; Testing — "the unit suite additionally runs as a pre-commit hook".
- Actual: no hook script in the repo, no `core.hooksPath`, nothing in `Makefile`.
  Both suites run in GitHub Actions on every push and PR (`.github/workflows/`).
- Why: never set up; CI covers the gate.
- Status: open. Either add the script (and a `make hooks` target to install it) or
  remove the sentence from the guide.
