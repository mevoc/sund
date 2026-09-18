package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mevoc/sund/internal/sigauth"
)

// DefaultTimeout bounds one request when Connect is used.
const DefaultTimeout = 15 * time.Second

// maxResponseBytes caps a response body the client will read.
const maxResponseBytes = 1 << 20

// Conn is how to reach one server: its base URL and the HTTP client that
// carries the transport-trust mode. It holds no key; principals wrap it.
type Conn struct {
	BaseURL string
	HTTP    *http.Client
}

// Connect returns a Conn for a parsed address, in that address's mode. This is
// the contract-conformant constructor and the one production callers should
// use.
func Connect(a Address) *Conn {
	return &Conn{BaseURL: a.BaseURL(), HTTP: a.httpClient(DefaultTimeout)}
}

// NewConn wraps an arbitrary base URL and HTTP client. It exists for tests and
// for a consumer that runs on the same host or private network as the relay
// (Sund's own compose file serves plain HTTP behind a proxy). It performs no
// transport-trust check of its own: a caller using it over a network takes on
// the contract's obligations itself. If hc is nil, http.DefaultClient is used.
func NewConn(baseURL string, hc *http.Client) *Conn {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Conn{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: hc}
}

// Health probes GET /health and returns the server's version string.
func (c *Conn) Health(ctx context.Context) (string, error) {
	var out struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := c.do(ctx, nil, http.MethodGet, "/health", nil, nil, &out); err != nil {
		return "", err
	}
	return out.Version, nil
}

// do performs one request. If key is non-nil the request is signed with it per
// internal/sigauth; extra headers (device id, sender key) are added by the
// caller. in is JSON-encoded as the body when non-nil; out is JSON-decoded from
// a 2xx response when non-nil. Non-2xx responses become *APIError.
func (c *Conn) do(ctx context.Context, key ed25519.PrivateKey, method, path string, extra http.Header, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if key != nil {
		if err := sign(req.Header, key, method, path, body); err != nil {
			return err
		}
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return wrapTransportErr(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			apiErr.Message = e.Error
		}
		return apiErr
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("sund: decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

// sign sets the timestamp, nonce and signature headers over the canonical
// string. The path signed is the URL path only, as the server verifies it.
func sign(h http.Header, key ed25519.PrivateKey, method, path string, body []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	n := hex.EncodeToString(nonce[:])
	sig := ed25519.Sign(key, sigauth.SigningString(method, path, ts, n, body))
	h.Set(sigauth.HeaderTimestamp, ts)
	h.Set(sigauth.HeaderNonce, n)
	h.Set(sigauth.HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

// GenerateKey returns a fresh Ed25519 keypair for any of the three principals.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
