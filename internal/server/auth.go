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

// sigEnvelope is the signature metadata and buffered body common to every
// signed request, on either plane.
type sigEnvelope struct {
	timestamp string
	nonce     string
	signature []byte
	body      []byte
}

// extractSignature reads and validates the signature envelope — presence,
// timestamp window, base64 signature — and buffers the body (restoring r.Body).
// It does not verify against any key; the caller supplies that, since the key
// source differs by plane (device identity vs. per-queue key).
func (s *Server) extractSignature(r *http.Request) (*sigEnvelope, bool) {
	ts := r.Header.Get(sigauth.HeaderTimestamp)
	nonce := r.Header.Get(sigauth.HeaderNonce)
	sigB64 := r.Header.Get(sigauth.HeaderSignature)
	if ts == "" || nonce == "" || sigB64 == "" {
		return nil, false
	}
	tsTime, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return nil, false
	}
	if skew := time.Since(tsTime); skew > s.clockSkew || skew < -s.clockSkew {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, false
	}
	return &sigEnvelope{timestamp: ts, nonce: nonce, signature: sig, body: body}, true
}

// verifyAndRecord verifies the envelope's signature over r against key, then
// records the nonce (scoped to principal) to reject replays. Verifying before
// recording keeps bogus requests from flooding the nonce cache. The nonce need
// only be remembered for the skew window, since a stale timestamp is already
// rejected by extractSignature.
func (s *Server) verifyAndRecord(r *http.Request, env *sigEnvelope, principal string, key ed25519.PublicKey) bool {
	msg := sigauth.SigningString(r.Method, r.URL.Path, env.timestamp, env.nonce, env.body)
	if !ed25519.Verify(key, msg, env.signature) {
		return false
	}
	tsTime, _ := time.Parse(time.RFC3339, env.timestamp)
	return s.nonces.checkAndAdd(principal+"\x00"+env.nonce, tsTime.Add(s.clockSkew))
}

// requireSignature authenticates a management-plane request by its device's
// Ed25519 identity key and, on success, attaches the calling device to the
// context. It rejects with a uniform 401 (missing headers, stale timestamp,
// unknown/revoked device, bad signature, or replay) to avoid leaking which
// check failed.
func (s *Server) requireSignature(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := r.Header.Get(sigauth.HeaderDeviceID)
		if deviceID == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		env, ok := s.extractSignature(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		dev, err := s.store.GetDevice(r.Context(), deviceID)
		if err != nil || dev.Revoked {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if !s.verifyAndRecord(r, env, deviceID, dev.PublicKey) {
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
