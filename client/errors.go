package client

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/mevoc/sund/internal/tlsid"
)

// ErrServerIdentity is wrapped by any error caused by the server failing the
// transport-trust check: a pinned fingerprint or chain failure (tlsid.ErrIdentity),
// or a WebPKI chain or hostname failure. The pinning contract (§5, §8.3) requires this to be
// distinguishable from an ordinary network error and never silently retried.
var ErrServerIdentity = errors.New("sund: server identity could not be verified")

// APIError is a non-2xx response from the server.
type APIError struct {
	StatusCode int
	Message    string // the server's "error" field, if any
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("sund: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("sund: HTTP %d: %s", e.StatusCode, e.Message)
}

// StatusCode returns the HTTP status behind err, or 0 if err is not an APIError.
func StatusCode(err error) int {
	var api *APIError
	if errors.As(err, &api) {
		return api.StatusCode
	}
	return 0
}

// wrapTransportErr maps a TLS verification failure onto ErrServerIdentity and
// passes every other error through unchanged.
func wrapTransportErr(err error) error {
	if err == nil {
		return nil
	}
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) || errors.Is(err, tlsid.ErrIdentity) {
		return fmt.Errorf("%w: %v", ErrServerIdentity, err)
	}
	return err
}
