package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func mintInvitation(t *testing.T, srv *Server, deviceID string, priv ed25519.PrivateKey) invitationResponse {
	t.Helper()
	rec := serve(srv, signWith(t, priv, deviceID, http.MethodPost, "/v1/invitations", nil, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d, want 201", rec.Code)
	}
	var resp invitationResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode mint: %v", err)
	}
	if resp.InvitationID == "" || resp.InvitationToken == "" {
		t.Fatalf("mint response missing id or token: %+v", resp)
	}
	return resp
}

func listInvitations(t *testing.T, srv *Server, deviceID string, priv ed25519.PrivateKey) []invitationView {
	t.Helper()
	rec := serve(srv, signWith(t, priv, deviceID, http.MethodGet, "/v1/invitations", nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", rec.Code)
	}
	var resp struct {
		Invitations []invitationView `json:"invitations"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	return resp.Invitations
}

func unsignedRegisterRequest(token string) *http.Request {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"token":%q,"public_key":%q}`, token, base64.StdEncoding.EncodeToString(pub)))
	return httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader(body))
}

func TestListInvitations(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)

	inv := mintInvitation(t, srv, deviceID, priv)

	got := listInvitations(t, srv, deviceID, priv)
	if len(got) != 1 || got[0].ID != inv.InvitationID {
		t.Fatalf("list = %+v, want the one minted invitation %q", got, inv.InvitationID)
	}
	if got[0].Expires == "" {
		t.Error("listed invitation missing expiry")
	}
}

func TestRevokeInvitationRemovesItAndBlocksUse(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)
	inv := mintInvitation(t, srv, deviceID, priv)

	rec := serve(srv, signWith(t, priv, deviceID, http.MethodPost, "/v1/invitations/"+inv.InvitationID+"/revoke", nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// Gone from the listing.
	if got := listInvitations(t, srv, deviceID, priv); len(got) != 0 {
		t.Fatalf("revoked invitation still listed: %+v", got)
	}

	// The token no longer registers a device.
	regRec := serve(srv, unsignedRegisterRequest(inv.InvitationToken))
	if regRec.Code != http.StatusUnauthorized {
		t.Fatalf("register with revoked token status = %d, want 401", regRec.Code)
	}
}

func TestRevokeUnknownInvitation(t *testing.T) {
	srv, st := newTestServer(t)
	deviceID, priv := registerDevice(t, srv, st)

	rec := serve(srv, signWith(t, priv, deviceID, http.MethodPost, "/v1/invitations/inv_nope/revoke", nil, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestListInvitationsRequiresSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := serve(srv, httptest.NewRequest(http.MethodGet, "/v1/invitations", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
