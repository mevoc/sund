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

Early. The first management-plane slice is in place; the transport plane
(pseudonymous queues, send/recv) is next. Implemented endpoints:

| Method & path              | Auth                 | Purpose                              |
| -------------------------- | -------------------- | ------------------------------------ |
| `GET /health`              | none                 | liveness                             |
| `POST /v1/devices/register`| one-time token       | enroll a device (bootstrap)          |
| `GET /v1/devices`          | Ed25519 signature    | list the account's devices           |
| `POST /v1/invitations`     | Ed25519 signature    | mint a token to pair another device  |

Signed requests carry `Sund-Device-Id`, `Sund-Timestamp`, `Sund-Nonce` and
`Sund-Signature` headers; the signature covers method, path, timestamp, nonce
and a hash of the body (see `internal/sigauth`). Accounts are provisioned by the
operator with `sund admin account create`.

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
