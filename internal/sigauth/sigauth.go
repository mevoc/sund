// Package sigauth defines the canonical form of a signed management-plane
// request. It is the one contract the server and every client (including the
// Python beaconsim test client) must reproduce byte-for-byte, so it lives alone
// with no dependencies beyond the standard library.
//
// A device signs, with its Ed25519 identity key, the newline-joined tuple:
//
//	METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(sha256(BODY))
//
// where PATH is the URL path (no query string), TIMESTAMP is the RFC3339 UTC
// string sent in the timestamp header, NONCE is a per-request random string, and
// BODY is the raw request body (empty for GET). The signature and metadata
// travel in the headers below.
package sigauth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Request header names carrying the signature and its inputs.
const (
	HeaderDeviceID  = "Sund-Device-Id"
	HeaderTimestamp = "Sund-Timestamp"
	HeaderNonce     = "Sund-Nonce"
	HeaderSignature = "Sund-Signature"

	// HeaderSenderKey carries the sender's per-queue Ed25519 public key on the
	// first SEND to an open queue, so the server can bind and thereafter verify
	// it (transport plane). Absent once the queue is bound.
	HeaderSenderKey = "Sund-Sender-Key"
)

// SigningString builds the exact byte sequence a client signs and the server
// verifies. body may be nil (treated as empty).
func SigningString(method, path, timestamp, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join(
		[]string{method, path, timestamp, nonce, hex.EncodeToString(sum[:])},
		"\n",
	))
}
