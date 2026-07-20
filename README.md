# Sund

> «Own the strait. The cargo stays sealed.»

A minimal, self-hostable, **blind** store-and-forward relay for end-to-end
encrypted messages between a user's devices, plus the device management that
makes that trustworthy. The server transports sealed envelopes; it never
interprets them. (Working name.)

**Spec:** [`docs/Sund-PRD.md`](docs/Sund-PRD.md) (current, v0.3) ·
[`docs/Sund-ImplementationGuide.md`](docs/Sund-ImplementationGuide.md) ·
[`docs/Sund-PriorArt.md`](docs/Sund-PriorArt.md)

## Status

Both planes work, with push wake-up and device revocation wired in; per-account
storage quota and the standalone blindness/operator audits are next. Implemented
endpoints:

| Method & path               | Auth                | Purpose                              |
| --------------------------- | ------------------- | ------------------------------------ |
| `GET /health`               | none                | liveness                             |
| `POST /v1/devices/register` | one-time token      | enroll a device (bootstrap)          |
| `GET /v1/devices`           | device signature    | list the account's devices           |
| `POST /v1/devices/{id}/revoke` | device signature | revoke a device (kills it + its queues) |
| `POST /v1/invitations`      | device signature    | mint a token to pair another device  |
| `PUT /v1/me/push`           | device signature    | register this device's wake-up endpoint |
| `POST /v1/queues`           | device signature    | create a blind queue you own         |
| `POST /v1/send/{sender_id}` | per-queue sender key | append an encrypted message          |
| `GET /v1/recv/{recipient_id}` | per-queue recipient key | drain your queue                  |
| `POST /v1/ack/{recipient_id}` | per-queue recipient key | delete acknowledged messages      |
| `POST /v1/retire/{recipient_id}` | per-queue recipient key | retire a queue (rotation)      |

**Revocation** is one atomic step: the target's identity key dies, its push
endpoint is cleared, and every queue it owns is retired with its messages
dropped. The account's other devices are pinged to refetch the list and rotate
their own queues. Any device in an account may revoke another (an admin-role
restriction, if wanted, is app-level policy).

**Wake-up** is a contentless ping — no payload, no queue id, only "check in".
The server pings a queue's owner when a message arrives (resolving queue → owner
device live, never as a stored link), and pings an account's other devices when
its device list changes. Android delivery is a self-hostable UnifiedPush/ntfy
distributor; the provider is pluggable (`internal/push`).

**Management plane** requests are signed by the device's Ed25519 identity key and
carry a `Sund-Device-Id` header. **Transport-plane** requests carry no device
identity — they are signed by a per-queue key and addressed only by the queue's
random recipient/sender ids, so the server never records who sends to whom. A
queue is created "open"; the first valid `send` binds the sender's key
(`Sund-Sender-Key`), SimpleX-style. Every signed request covers method, path,
timestamp, nonce and a hash of the body (see `internal/sigauth`); payloads are
opaque ciphertext. Accounts are provisioned with `sund admin account create`.

## Stack

Go + SQLite via the pure-Go `modernc.org/sqlite` driver (`CGO_ENABLED=0`): one
static binary, one database file, no C toolchain. The system-test client
(`beaconsim`) is Python — deliberately a different language from the server, so
the tests exercise the API as an independent client.

## Develop

Requires **Go 1.25+** (floor set by the `modernc.org/sqlite` driver; the stdlib
router itself only needs 1.22) and **[uv](https://docs.astral.sh/uv/)**.

```sh
make build      # compile the sund binary
make test       # unit suite   (Go, in-process)
make test-sys   # system suite (Python beaconsim boots the real binary)
make test-all   # both
```

Run it:

```sh
./sund serve --addr :5870 --db sund.db
curl localhost:5870/health      # {"status":"ok","version":"0.0.0-dev"}
```
