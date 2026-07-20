package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// registerSecondDevice enrolls another device into an existing device's account
// (via a signed invitation) and returns its id and private key.
func registerSecondDevice(t *testing.T, srv *Server, inviterID string, inviterPriv ed25519.PrivateKey) (string, ed25519.PrivateKey) {
	t.Helper()
	invRec := serve(srv, signWith(t, inviterPriv, inviterID, http.MethodPost, "/v1/invitations", nil, nil))
	if invRec.Code != http.StatusCreated {
		t.Fatalf("invitation status = %d, want 201", invRec.Code)
	}
	var inv invitationResponse
	if err := json.NewDecoder(invRec.Body).Decode(&inv); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"token":%q,"public_key":%q}`, inv.InvitationToken, base64.StdEncoding.EncodeToString(pub)))
	rec := serve(srv, httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201", rec.Code)
	}
	var resp registerResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	return resp.DeviceID, priv
}

func TestRevokeDeviceKillsIdentityAndQueues(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	bID, bPriv := registerSecondDevice(t, srv, aID, aPriv)

	// B owns a queue.
	bRecipientID, _, _ := createQueueForDevice(t, srv, bID, bPriv)

	// A revokes B.
	rec := serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/devices/"+bID+"/revoke", nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// B's signed management request now fails.
	listRec := serve(srv, signWith(t, bPriv, bID, http.MethodGet, "/v1/devices", nil, nil))
	if listRec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device list status = %d, want 401", listRec.Code)
	}

	// B's queue is retired: draining it 404s.
	q, err := st.GetQueueByRecipient(context.Background(), bRecipientID)
	if err != nil {
		t.Fatalf("GetQueueByRecipient: %v", err)
	}
	if !q.Retired {
		t.Fatal("revoked device's queue should be retired")
	}
}

func TestRevokedDeviceStillListedAsRevoked(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)
	bID, _ := registerSecondDevice(t, srv, aID, aPriv)

	serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/devices/"+bID+"/revoke", nil, nil))

	rec := serve(srv, signWith(t, aPriv, aID, http.MethodGet, "/v1/devices", nil, nil))
	var resp struct {
		Devices []deviceView `json:"devices"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	var found *deviceView
	for i := range resp.Devices {
		if resp.Devices[i].ID == bID {
			found = &resp.Devices[i]
		}
	}
	if found == nil {
		t.Fatal("revoked device should still appear in the list")
	}
	if !found.Revoked {
		t.Fatal("revoked device should be flagged revoked in the list")
	}
}

func TestCrossAccountRevokeRejected(t *testing.T) {
	srv, st := newTestServer(t)
	aID, aPriv := registerDevice(t, srv, st)  // account 1
	victimID, _ := registerDevice(t, srv, st) // account 2 (separate)

	rec := serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/devices/"+victimID+"/revoke", nil, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-account revoke status = %d, want 404", rec.Code)
	}

	// The victim is untouched.
	victim, err := st.GetDevice(context.Background(), victimID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if victim.Revoked {
		t.Fatal("a device in another account must not be revocable")
	}
}

func TestRevokePingsPeers(t *testing.T) {
	srv, st, fp := newServerWithPinger(t)
	aID, aPriv := registerDevice(t, srv, st)
	if err := st.UpdatePushEndpoint(context.Background(), aID, "https://push.example/a"); err != nil {
		t.Fatalf("UpdatePushEndpoint: %v", err)
	}
	bID, _ := registerSecondDevice(t, srv, aID, aPriv)
	// Drain the ping caused by B's registration.
	fp.await(t)

	rec := serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/devices/"+bID+"/revoke", nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", rec.Code)
	}
	if got := fp.await(t); got.endpoint != "https://push.example/a" {
		t.Errorf("revoke pinged %q, want A's endpoint", got.endpoint)
	}
}
