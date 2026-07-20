package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/store"
)

type registerRequest struct {
	Token        string `json:"token"`
	PublicKey    string `json:"public_key"` // base64 (standard) Ed25519 public key
	PushEndpoint string `json:"push_endpoint"`
	Capabilities string `json:"capabilities"`
}

type registerResponse struct {
	DeviceID  string `json:"device_id"`
	AccountID string `json:"account_id"`
}

// handleRegister enrolls a device by consuming a one-time invitation token. It
// is the one unsigned management-plane route: the device has no identity yet, so
// the token is the credential.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid public_key")
		return
	}

	dev, err := s.store.RegisterDevice(r.Context(), req.Token, ed25519.PublicKey(pub), req.PushEndpoint, req.Capabilities)
	switch {
	case errors.Is(err, store.ErrInvalidInvitation):
		writeError(w, http.StatusUnauthorized, "invalid or expired invitation")
		return
	case err != nil:
		log.Printf("register: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, registerResponse{DeviceID: dev.ID, AccountID: dev.AccountID})
}

type deviceView struct {
	ID           string `json:"id"`
	PublicKey    string `json:"public_key"` // base64 (standard)
	PushEndpoint string `json:"push_endpoint"`
	Capabilities string `json:"capabilities"`
	Created      string `json:"created"`
	LastSeen     string `json:"last_seen"`
	Revoked      bool   `json:"revoked"`
}

func toDeviceView(d store.Device) deviceView {
	return deviceView{
		ID:           d.ID,
		PublicKey:    base64.StdEncoding.EncodeToString(d.PublicKey),
		PushEndpoint: d.PushEndpoint,
		Capabilities: d.Capabilities,
		Created:      d.Created.UTC().Format(time.RFC3339),
		LastSeen:     d.LastSeen.UTC().Format(time.RFC3339),
		Revoked:      d.Revoked,
	}
}

type invitationResponse struct {
	InvitationToken string `json:"invitation_token"`
	Expires         string `json:"expires"`
}

// handleCreateInvitation mints a single-use enrollment token for the caller's
// account (implementation guide, Walkthrough 2, step 1). Signed: only an
// existing device may invite another into its account.
func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	token, expires, err := s.store.CreateInvitation(r.Context(), dev.AccountID, defaultInvitationTTL)
	if err != nil {
		log.Printf("create invitation: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, invitationResponse{
		InvitationToken: token,
		Expires:         expires.UTC().Format(time.RFC3339),
	})
}

// handleListDevices returns every device in the caller's account. The public
// keys are included so peers can verify a newly paired device's identity
// against the list (implementation guide, Walkthrough 2).
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	devs, err := s.store.ListDevices(r.Context(), dev.AccountID)
	if err != nil {
		log.Printf("list devices: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	views := make([]deviceView, len(devs))
	for i, d := range devs {
		views[i] = toDeviceView(d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": views})
}
