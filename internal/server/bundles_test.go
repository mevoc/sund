package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setBundle(t *testing.T, srv *Server, deviceID string, priv ed25519.PrivateKey, blob []byte) int {
	t.Helper()
	body := []byte(fmt.Sprintf(`{"bundle":%q}`, base64.StdEncoding.EncodeToString(blob)))
	return serve(srv, signWith(t, priv, deviceID, http.MethodPut, "/v1/me/bundle", body, nil)).Code
}

func TestPublishAndFetchBundle(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	bID, bPriv := registerSecondDevice(t, srv, aID, aPriv)

	blob := []byte("A's prekey bundle")
	if code := setBundle(t, srv, aID, aPriv, blob); code != http.StatusOK {
		t.Fatalf("set bundle status = %d, want 200", code)
	}

	// B (same account) fetches A's bundle and gets the exact bytes back.
	rec := serve(srv, signWith(t, bPriv, bID, http.MethodGet, "/v1/devices/"+aID+"/bundle", nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get bundle status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp bundleResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, err := base64.StdEncoding.DecodeString(resp.Bundle)
	if err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("bundle round-trip mismatch: got %q", got)
	}
}

func TestFetchMissingBundle(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	rec := serve(srv, signWith(t, aPriv, aID, http.MethodGet, "/v1/devices/"+aID+"/bundle", nil, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestFetchBundleCrossAccountRejected(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st) // account 1
	if code := setBundle(t, srv, aID, aPriv, []byte("public-keys")); code != http.StatusOK {
		t.Fatalf("set bundle status = %d", code)
	}

	strangerID, strangerPriv := registerDevice(t, srv, st) // account 2
	rec := serve(srv, signWith(t, strangerPriv, strangerID, http.MethodGet, "/v1/devices/"+aID+"/bundle", nil, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-account fetch status = %d, want 404", rec.Code)
	}
}

func TestFetchRevokedDeviceBundle(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	bID, bPriv := registerSecondDevice(t, srv, aID, aPriv)

	if code := setBundle(t, srv, bID, bPriv, []byte("B's bundle")); code != http.StatusOK {
		t.Fatalf("set bundle status = %d", code)
	}
	serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/devices/"+bID+"/revoke", nil, nil))

	rec := serve(srv, signWith(t, aPriv, aID, http.MethodGet, "/v1/devices/"+bID+"/bundle", nil, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoked device bundle status = %d, want 404", rec.Code)
	}
}

func TestSetBundleTooLarge(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	code := setBundle(t, srv, aID, aPriv, []byte(strings.Repeat("x", maxBundleBytes+1)))
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized bundle status = %d, want 413", code)
	}
}

func TestSetBundleRequiresSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/me/bundle", bytes.NewReader([]byte(`{"bundle":"AAAA"}`)))
	rec := serve(srv, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
