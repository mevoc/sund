package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mevoc/sund/internal/sigauth"
	"github.com/mevoc/sund/internal/store"
)

func newTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Config{Version: "test"}, st), st
}

// registerDevice drives the real HTTP register flow and returns the new device
// id together with the private key it was enrolled under.
func registerDevice(t *testing.T, srv *Server, st *store.Store) (deviceID string, priv ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard", 0, store.AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, store.RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, token, base64.StdEncoding.EncodeToString(pub))
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp registerResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	return resp.DeviceID, priv
}

// signedRequest builds a signed GET request for path.
func signedRequest(deviceID string, priv ed25519.PrivateKey, method, path string, ts time.Time, nonce string) *http.Request {
	tsStr := ts.UTC().Format(time.RFC3339)
	msg := sigauth.SigningString(method, path, tsStr, nonce, nil)
	sig := ed25519.Sign(priv, msg)
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(sigauth.HeaderDeviceID, deviceID)
	req.Header.Set(sigauth.HeaderTimestamp, tsStr)
	req.Header.Set(sigauth.HeaderNonce, nonce)
	req.Header.Set(sigauth.HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return req
}

func randNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want ok", body["status"])
	}
}

func TestRegisterRejectsBadToken(t *testing.T) {
	srv, _ := newTestServer(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := fmt.Sprintf(`{"token":"nope","public_key":%q}`, base64.StdEncoding.EncodeToString(pub))
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/register", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRegisterRejectsBadPublicKey(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/register",
		strings.NewReader(`{"token":"x","public_key":"not-base64!!"}`))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSignedListDevices(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)

	req := signedRequest(deviceID, priv, http.MethodGet, "/v1/devices", time.Now(), randNonce(t))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Devices []deviceView `json:"devices"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].ID != deviceID {
		t.Fatalf("devices = %+v, want exactly the caller %q", resp.Devices, deviceID)
	}
}

func TestSignedRequestRejectsForgedSignature(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, _ := registerDevice(t, srv, st)

	// Sign with an unrelated key the server never saw.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	req := signedRequest(deviceID, wrongPriv, http.MethodGet, "/v1/devices", time.Now(), randNonce(t))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSignedRequestRejectsStaleTimestamp(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)

	stale := time.Now().Add(-10 * time.Minute) // beyond the 5m window
	req := signedRequest(deviceID, priv, http.MethodGet, "/v1/devices", stale, randNonce(t))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSignedRequestRejectsReplay(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)

	ts := time.Now()
	nonce := randNonce(t)

	first := signedRequest(deviceID, priv, http.MethodGet, "/v1/devices", ts, nonce)
	rec1 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec1, first)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rec1.Code)
	}

	// Same device, same nonce, same timestamp → replay.
	replay := signedRequest(deviceID, priv, http.MethodGet, "/v1/devices", ts, nonce)
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, replay)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec2.Code)
	}
}

func TestSignedInvitationEnablesSecondDevice(t *testing.T) {
	srv, st := newTestServer(t)
	deviceA, privA := registerDevice(t, srv, st)

	// Device A mints an invitation for its own account via the signed endpoint.
	req := signedRequest(deviceA, privA, http.MethodPost, "/v1/invitations", time.Now(), randNonce(t))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create invitation status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var inv invitationResponse
	if err := json.NewDecoder(rec.Body).Decode(&inv); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	// A second device registers with that token and joins the same account.
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	body := fmt.Sprintf(`{"token":%q,"public_key":%q}`, inv.InvitationToken, base64.StdEncoding.EncodeToString(pubB))
	regReq := httptest.NewRequest(http.MethodPost, "/v1/devices/register", strings.NewReader(body))
	regRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(regRec, regReq)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register B status = %d, want 201", regRec.Code)
	}

	// A now sees both devices.
	listReq := signedRequest(deviceA, privA, http.MethodGet, "/v1/devices", time.Now(), randNonce(t))
	listRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRec, listReq)
	var resp struct {
		Devices []deviceView `json:"devices"`
	}
	if err := json.NewDecoder(listRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Devices) != 2 {
		t.Fatalf("account has %d devices, want 2", len(resp.Devices))
	}
}

func TestUnsignedListDevicesRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
