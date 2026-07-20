package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/push"
)

// pingTimeout bounds a single wake-up delivery attempt.
const pingTimeout = 10 * time.Second

// maxPushEndpointLen caps a stored push endpoint URL.
const maxPushEndpointLen = 2048

// wakeQueueOwner pings the device that owns a queue after a message arrives —
// the runtime "push-ping fan-in" the threat model documents: queue -> owner is
// resolved live, never stored as a sender link.
func (s *Server) wakeQueueOwner(ownerDevice string, priority push.Priority) {
	dev, err := s.store.GetDevice(context.Background(), ownerDevice)
	if err != nil || dev.Revoked || dev.PushEndpoint == "" {
		return
	}
	s.dispatchPing(dev.PushEndpoint, priority)
}

// wakeAccountDevices pings every other live device in an account (used on
// device-list changes: registration now, revocation later). Best-effort — a
// missed ping only costs latency, since clients also refetch before pairing.
func (s *Server) wakeAccountDevices(accountID, exceptDeviceID string) {
	devs, err := s.store.ListDevices(context.Background(), accountID)
	if err != nil {
		log.Printf("wake account: %v", err)
		return
	}
	for _, d := range devs {
		if d.ID == exceptDeviceID || d.Revoked || d.PushEndpoint == "" {
			continue
		}
		s.dispatchPing(d.PushEndpoint, push.Normal)
	}
}

// dispatchPing fires a ping asynchronously so a slow or unreachable distributor
// never blocks the API response. Delivery is best-effort; failures are logged.
func (s *Server) dispatchPing(endpoint string, priority push.Priority) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		defer cancel()
		if err := s.pinger.Ping(ctx, endpoint, priority); err != nil {
			log.Printf("push ping: %v", err)
		}
	}()
}

type updatePushRequest struct {
	PushEndpoint string `json:"push_endpoint"`
}

// handleUpdatePush registers or updates the calling device's wake-up endpoint
// (e.g. a UnifiedPush URL). Signed; a device sets only its own.
func (s *Server) handleUpdatePush(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req updatePushRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.PushEndpoint) > maxPushEndpointLen {
		writeError(w, http.StatusBadRequest, "push_endpoint too long")
		return
	}
	if err := s.store.UpdatePushEndpoint(r.Context(), dev.ID, req.PushEndpoint); err != nil {
		log.Printf("update push: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
