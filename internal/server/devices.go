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

	"github.com/mevoc/sund/internal/push"
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

	// Device-list change: wake the account's other devices so they refetch.
	s.wakeAccountDevices(dev.AccountID, dev.ID)

	writeJSON(w, http.StatusCreated, registerResponse{DeviceID: dev.ID, AccountID: dev.AccountID})
}

// handleRevoke revokes a device in the caller's account. Revoking ANOTHER device
// is admin-only, which in a flat account is every device (PRD 0.3 behaviour) and
// in a managed one is the admins. Revoking yourself is always allowed, whatever
// your role: it is the only remedy a member has against an admin, and
// withholding it would protect nothing. Cross-account targets 404 without
// confirming they exist.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	caller, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	targetID := r.PathValue("id")

	target, err := s.store.GetDevice(r.Context(), targetID)
	if errors.Is(err, store.ErrDeviceNotFound) || (target != nil && target.AccountID != caller.AccountID) {
		writeError(w, http.StatusNotFound, "no such device")
		return
	}
	if err != nil {
		log.Printf("revoke lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Revoking another device is an administrative act; revoking yourself is not.
	if targetID != caller.ID {
		if err := store.RequireAdmin(caller); err != nil {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
	}

	// Capture the target's wake-up endpoint before revoking: RevokeDevice clears
	// it inside its transaction, and wakeAccountDevices skips revoked devices and
	// empty endpoints, so after this point there is nothing left to ping with.
	targetEndpoint := target.PushEndpoint

	switch err := s.store.RevokeDevice(r.Context(), caller.ID, targetID); {
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, http.StatusConflict, "account would lose its last admin")
		return
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no such device")
		return
	case err != nil:
		log.Printf("revoke: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Device-list change: wake the account's other devices so they refetch,
	// drop the revoked device's queues, and rotate/re-key their own. Exclude the
	// caller, which is the device that performed the act — the target is skipped
	// anyway, being revoked with a cleared endpoint by now.
	s.wakeAccountDevices(caller.AccountID, caller.ID)

	// And wake the target itself. It is the device the act was performed on and
	// the one with most reason to be told, and family-beacon's roster spec
	// requires that a removed device is told when it is reachable. Best-effort
	// like every ping: an unreachable target learns from its next request, which
	// fails closed. Normal priority deliberately — the urgency hint is a
	// disclosure (PRD, decision 18) and being revoked does not warrant spending
	// it.
	if targetEndpoint != "" && targetID != caller.ID {
		s.dispatchPing(targetEndpoint, push.Normal)
	}

	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

type deviceView struct {
	ID string `json:"id"`
	// Role is peer-readable on purpose: authority over other devices must be
	// visible to the devices it is held over. Contrast quota_bytes, which is
	// deliberately absent (PRD, decision 16).
	Role      string `json:"role"`
	PublicKey string `json:"public_key"` // base64 (standard)
	// PushEndpoint is returned only for the calling device, and omitted for
	// peers. A wake-up URL is not a fact about a device, it is a capability over
	// it: on a bearer-URL distributor such as a default ntfy topic, holding a
	// peer's endpoint is the ability to wake or spam that device — outside Sund
	// entirely, and beyond the reach of revocation or quota. No client needs a
	// peer's endpoint (pings are the server's to send), so publishing it bought
	// nothing and sold that. A device may still read back its own, which is a
	// diagnostic and confers nothing over anyone (PRD, decision 20).
	PushEndpoint string `json:"push_endpoint,omitempty"`
	Capabilities string `json:"capabilities"`
	Created      string `json:"created"`
	LastSeen     string `json:"last_seen"`
	Revoked      bool   `json:"revoked"`
}

// toDeviceView renders a device for the list. callerID is the device asking, so
// that its own push endpoint comes back while its peers' do not.
func toDeviceView(d store.Device, callerID string) deviceView {
	endpoint := ""
	if d.ID == callerID {
		endpoint = d.PushEndpoint
	}
	return deviceView{
		ID:           d.ID,
		Role:         d.Role,
		PublicKey:    base64.StdEncoding.EncodeToString(d.PublicKey),
		PushEndpoint: endpoint,
		Capabilities: d.Capabilities,
		Created:      d.Created.UTC().Format(time.RFC3339),
		LastSeen:     d.LastSeen.UTC().Format(time.RFC3339),
		Revoked:      d.Revoked,
	}
}

type invitationResponse struct {
	InvitationToken string `json:"invitation_token"`
	InvitationID    string `json:"invitation_id"`
	Expires         string `json:"expires"`
}

// handleCreateInvitation mints a single-use enrollment token for the caller's
// account (implementation guide, Walkthrough 2, step 1). Signed: only an
// existing device may invite another into its account. The response carries the
// non-secret invitation id so the caller can later list or revoke it.
func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := store.RequireAdmin(dev); err != nil {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	// An empty body is fine — grants_role then defaults to member in a managed
	// account, and is normalised to admin in a flat one — but a malformed body is
	// not, or a typo'd field would silently yield the default role.
	var req createInvitationRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if req.GrantsRole != "" && req.GrantsRole != store.RoleAdmin && req.GrantsRole != store.RoleMember {
		writeError(w, http.StatusBadRequest, "grants_role must be admin or member")
		return
	}
	token, inv, err := s.store.CreateInvitation(r.Context(), dev.AccountID, defaultInvitationTTL, req.GrantsRole)
	if err != nil {
		log.Printf("create invitation: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Minting is an administrative act: it wakes the account so an invitation
	// cannot be minted unobserved (PRD, propagation).
	s.wakeAccountDevices(dev.AccountID, dev.ID)
	writeJSON(w, http.StatusCreated, invitationResponse{
		InvitationToken: token,
		InvitationID:    inv.ID,
		Expires:         inv.Expires.UTC().Format(time.RFC3339),
	})
}

type invitationView struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Expires string `json:"expires"`
}

// handleListInvitations returns the account's outstanding (unconsumed,
// unrevoked, unexpired) invitations. Tokens are never included.
func (s *Server) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	invs, err := s.store.ListInvitations(r.Context(), dev.AccountID)
	if err != nil {
		log.Printf("list invitations: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	views := make([]invitationView, len(invs))
	for i, inv := range invs {
		views[i] = invitationView{
			ID:      inv.ID,
			Created: inv.Created.UTC().Format(time.RFC3339),
			Expires: inv.Expires.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitations": views})
}

// handleRevokeInvitation kills a mis-shared invitation before it is used. Scoped
// to the caller's account; an unknown or already-dead invitation 404s.
func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	revoked, err := s.store.RevokeInvitation(r.Context(), dev.AccountID, r.PathValue("id"))
	if err != nil {
		log.Printf("revoke invitation: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !revoked {
		writeError(w, http.StatusNotFound, "no such invitation")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
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
		views[i] = toDeviceView(d, dev.ID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": views})
}

type quotaView struct {
	QuotaBytes        int64 `json:"quota_bytes"`         // this device's ceiling; 0 = none
	StoredBytes       int64 `json:"stored_bytes"`        // live payloads in queues it owns
	AccountQuotaBytes int64 `json:"account_quota_bytes"` // the shared ceiling; 0 = none
}

// handleGetQuota returns the calling device's own storage ceiling and usage.
// Self-scoped by construction: it reads the authenticated device and takes no
// target, so a member cannot ask about a peer. That is the whole point — a
// ceiling is withheld from peers (PRD, decision 16), and this read is what lets
// the capped device tell "I am full" from "someone capped me".
//
// It carries the account ceiling, a constant that binds every device equally, so
// a device can explain a refusal it hits while under its own ceiling. It must
// never carry account *usage*, which would be an activity signal about peers.
func (s *Server) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	used, err := s.store.DeviceStoredBytes(r.Context(), dev.ID)
	if err != nil {
		log.Printf("device stored bytes: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	accountQuota, err := s.store.AccountQuotaBytes(r.Context(), dev.AccountID)
	if err != nil {
		log.Printf("account quota: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, quotaView{
		QuotaBytes:        dev.QuotaBytes,
		StoredBytes:       used,
		AccountQuotaBytes: accountQuota,
	})
}

type createInvitationRequest struct {
	GrantsRole string `json:"grants_role"`
}

type setRoleRequest struct {
	Role string `json:"role"`
}

// handleSetRole promotes or demotes a device in the caller's account. Admin
// only, and refused outright in a flat account: flat means every device is an
// admin as a property of the account, not a coincidence of the current rows, so
// there is nothing to promote, nothing to demote, and no walking a flat account
// into a managed one one demotion at a time (PRD, decision 12).
func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	caller, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := store.RequireAdmin(caller); err != nil {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	targetID := r.PathValue("id")

	var req setRoleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	switch err := s.store.SetDeviceRole(r.Context(), caller.AccountID, targetID, req.Role); {
	case errors.Is(err, store.ErrRoleChangeNotApplicable):
		writeError(w, http.StatusConflict, "roles are not changeable in a flat account")
		return
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, http.StatusConflict, "account would lose its last admin")
		return
	case errors.Is(err, store.ErrDeviceNotFound):
		writeError(w, http.StatusNotFound, "no such device")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}

	// A role change is an administrative act: it pings every device in the
	// account except the one that performed it.
	s.wakeAccountDevices(caller.AccountID, caller.ID)

	writeJSON(w, http.StatusOK, map[string]string{"role": req.Role})
}
