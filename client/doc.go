// Package client is the Go implementation of the Sund client contract: the
// server address and transport-trust modes of docs/Sund-Pinning-Contract.md,
// request signing (internal/sigauth), and typed calls for both planes — the
// management plane a device authenticates to with its identity key, and the
// transport plane of pseudonymous per-queue keys.
//
// It is deliberately thin. It does not encrypt payloads: Sund transports sealed
// envelopes it never interprets, and the encryption is the consumer's choice
// (tests/beaconsim uses an X25519 sealed box; family-beacon runs a ratchet).
// A caller hands Send ciphertext and gets ciphertext back from Recv.
//
// Three principals map onto three types:
//
//   - Device — an enrolled device (Register, or NewDevice from stored identity).
//     Signs management-plane requests: device list, invitations, push endpoint,
//     key bundles, and queue creation.
//   - Recipient — the owner side of one queue. Signs recv/ack/retire with the
//     per-queue recipient key.
//   - Sender — the pseudonymous writer side of one queue. Signs send with the
//     per-queue sender key, which the server binds on the first send.
//
// All calls are blocking, take a context, and return *APIError for non-2xx
// responses. A connection refused by the transport-trust check returns an
// error wrapping ErrServerIdentity, never a generic network error, so a caller
// can (and per the contract must) tell an intercepting network from an absent
// one.
package client
