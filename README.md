# Sund

[![CI](https://github.com/mevoc/sund/actions/workflows/ci.yml/badge.svg)](https://github.com/mevoc/sund/actions/workflows/ci.yml)

> «Own the strait. The cargo stays sealed.»

A minimal, self-hostable, **blind** store-and-forward relay for end-to-end
encrypted messages between a user's devices, plus the device management that
makes that trustworthy. The server transports sealed envelopes; it never
interprets them. (Working name.)

**Spec:** [`docs/Sund-PRD.md`](docs/Sund-PRD.md) (current, v0.3) ·
[`docs/Sund-ImplementationGuide.md`](docs/Sund-ImplementationGuide.md) ·
[`docs/Sund-PriorArt.md`](docs/Sund-PriorArt.md)

## Status

Both planes work, with push wake-up, device revocation, and per-account storage
quota wired in, and the blindness (S8) and operator-survival (S9) audits pass.
The remaining items are open design decisions (iOS APNS gateway, key bundles,
queue-rotation policy). Implemented endpoints:

| Method & path               | Auth                | Purpose                              |
| --------------------------- | ------------------- | ------------------------------------ |
| `GET /health`               | none                | liveness                             |
| `POST /v1/devices/register` | one-time token      | enroll a device (bootstrap)          |
| `GET /v1/devices`           | device signature    | list the account's devices           |
| `POST /v1/devices/{id}/revoke` | device signature | revoke a device (kills it + its queues) |
| `POST /v1/invitations`      | device signature    | mint a token to pair another device  |
| `GET /v1/invitations`       | device signature    | list outstanding invitations         |
| `POST /v1/invitations/{id}/revoke` | device signature | revoke an invitation before use   |
| `PUT /v1/me/push`           | device signature    | register this device's wake-up endpoint |
| `PUT /v1/me/bundle`         | device signature    | publish this device's key bundle     |
| `GET /v1/devices/{id}/bundle` | device signature  | fetch a peer's key bundle (async pairing) |
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

**Storage quota** is per account, attributed to the queue owner's side (so
senders stay pseudonymous). A send that would push an account's stored payloads
past its cap is refused with `507`; space frees as messages are acked or expire.
Set it with `sund admin account create --quota-bytes N` (or a named `--quota`
class). A quota of 0 means unlimited, so upgrading an existing database never
retroactively caps its accounts.

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

## Configuration

`serve` and `admin` read defaults from the environment, and an explicit flag
still wins:

| Env var       | Flag        | Default    | Applies to        |
| ------------- | ----------- | ---------- | ----------------- |
| `SUND_ADDR`   | `--addr`    | `:5870`    | `serve`           |
| `SUND_DB`     | `--db`      | `sund.db`  | `serve`, `admin`  |
| `SUND_TLS_DIR`| `--tls-dir` | *(unset)*  | `serve`, `cert`   |

## Transport security (pinned TLS)

By default the server speaks plain HTTP, meant to sit behind a TLS-terminating
reverse proxy (ordinary WebPKI). Alternatively, `serve --tls-dir DIR` serves
HTTPS itself with a **fingerprint-pinned** self-signed certificate — no CA, no
domain, works on a bare IP or LAN (the SimpleX model):

```sh
# print the pinned address for the onboarding QR (generates certs on first run)
sund cert fingerprint --tls-dir ./certs --host beacon.example:5870
# → sund://beacon.example:5870#<fingerprint>

sund serve --tls-dir ./certs --addr :5870
```

The address embeds the SHA-256 of a long-lived offline CA; that CA signs a
rotatable leaf used for the live handshake, so the leaf can be rotated (delete
`server.crt`/`server.key`) without changing the pin. A client pins the fingerprint
from the address and rejects any certificate that doesn't match — a first-connect
MITM is detected, not trusted. `tests/beaconsim/pinning.py` is a reference client.

## Container image

CI builds a multi-arch (amd64/arm64) image on every push to `main` and publishes
it to the GitHub Container Registry. It is a distroless, non-root static binary;
the database lives on the `/data` volume. `sund health` probes `/health` and
exits non-zero if the server is down, so the image can declare a healthcheck
despite having no shell.

The repo ships a minimal single-service [`compose.yaml`](compose.yaml) and
[`.env.example`](.env.example):

```sh
cp .env.example .env          # optional: set SUND_IMAGE / SUND_PORT
docker compose up -d
docker compose exec sund /sund admin account create   # first account + invite
```

Or run it directly:

```sh
docker run -d --name sund -p 5870:5870 -v sund-data:/data ghcr.io/mevoc/sund:latest
docker exec sund /sund admin account create
```

The server speaks plain HTTP; terminate TLS at a reverse proxy in front of it. A
full self-hosting stack (with a UnifiedPush distributor and TLS) is a consumer
concern — see `../family-beacon`.
