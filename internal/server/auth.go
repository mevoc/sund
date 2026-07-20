package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/mevoc/sund/internal/sigauth"
	"github.com/mevoc/sund/internal/store"
)

type deviceCtxKey struct{}

// deviceFromContext returns the authenticated device attached by
// requireSignature.
func deviceFromContext(ctx context.Context) (*store.Device, bool) {
	d, ok := ctx.Value(deviceCtxKey{}).(*store.Device)
	return d, ok
}

// requireSignature authenticates a management-plane request by its Ed25519
// signature and, on success, attaches the calling device to the context.
//
// It rejects (401, uniformly, to avoid leaking which check failed):
//   - missing or malformed signature headers,
//   - a timestamp outside the accepted clock-skew window (stale or future),
//   - an unknown or revoked device,
//   - a signature that does not verify against the device's public key,
//   - a replayed (device, nonce) pair within the skew window.
func (s *Server) requireSignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := r.Header.Get(sigauth.HeaderDeviceID)
		ts := r.Header.Get(sigauth.HeaderTimestamp)
		nonce := r.Header.Get(sigauth.HeaderNonce)
		sigB64 := r.Header.Get(sigauth.HeaderSignature)
		if deviceID == "" || ts == "" || nonce == "" || sigB64 == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		tsTime, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if skew := time.Since(tsTime); skew > s.clockSkew || skew < -s.clockSkew {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		dev, err := s.store.GetDevice(r.Context(), deviceID)
		if err != nil || dev.Revoked {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		msg := sigauth.SigningString(r.Method, r.URL.Path, ts, nonce, body)
		if !ed25519.Verify(dev.PublicKey, msg, sig) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Reject replays only after the signature is proven valid, so bogus
		// requests cannot flood the nonce cache. The nonce is bound to the
		// signed timestamp, so it need only be remembered for the skew window.
		if !s.nonces.checkAndAdd(deviceID+"\x00"+nonce, tsTime.Add(s.clockSkew)) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		_ = s.store.TouchLastSeen(r.Context(), deviceID)
		ctx := context.WithValue(r.Context(), deviceCtxKey{}, dev)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// nonceCache remembers recently seen (device, nonce) keys until their expiry, to
// reject replays. It is in-memory by design: the PRD data model stores no
// nonces, and replay protection only needs to span the clock-skew window.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{seen: make(map[string]time.Time)}
}

// checkAndAdd records key with the given expiry and reports whether it was new.
// A key still within its expiry window is a replay and returns false.
func (c *nonceCache) checkAndAdd(key string, expiry time.Time) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, exp := range c.seen {
		if exp.Before(now) {
			delete(c.seen, k)
		}
	}
	if exp, ok := c.seen[key]; ok && exp.After(now) {
		return false
	}
	c.seen[key] = expiry
	return true
}
