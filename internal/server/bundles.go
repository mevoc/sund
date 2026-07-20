package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/store"
)

// maxBundleBytes caps a published key bundle. Bundles are small — a handful of
// public keys and prekeys — so a tight cap is fine and bounds abuse.
const maxBundleBytes = 8 << 10 // 8 KiB

type bundleRequest struct {
	Bundle string `json:"bundle"` // base64 opaque key material
}

// handleSetBundle stores the calling device's key bundle (a dead-drop the server
// never interprets). Signed; a device sets only its own.
func (s *Server) handleSetBundle(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req bundleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Bundle)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bundle")
		return
	}
	if len(blob) == 0 {
		writeError(w, http.StatusBadRequest, "empty bundle")
		return
	}
	if len(blob) > maxBundleBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "bundle too large")
		return
	}
	if err := s.store.SetBundle(r.Context(), dev.ID, blob); err != nil {
		log.Printf("set bundle: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type bundleResponse struct {
	Bundle  string `json:"bundle"`
	Updated string `json:"updated"`
}

// handleGetBundle returns another device's key bundle so the caller can pair with
// it asynchronously. Same account only; a missing, revoked, or cross-account
// target 404s without confirming which.
func (s *Server) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	caller, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	targetID := r.PathValue("id")

	target, err := s.store.GetDevice(r.Context(), targetID)
	if errors.Is(err, store.ErrDeviceNotFound) || (target != nil && (target.AccountID != caller.AccountID || target.Revoked)) {
		writeError(w, http.StatusNotFound, "no such bundle")
		return
	}
	if err != nil {
		log.Printf("get bundle lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	blob, updated, err := s.store.GetBundle(r.Context(), targetID)
	if errors.Is(err, store.ErrBundleNotFound) {
		writeError(w, http.StatusNotFound, "no such bundle")
		return
	}
	if err != nil {
		log.Printf("get bundle: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, bundleResponse{
		Bundle:  base64.StdEncoding.EncodeToString(blob),
		Updated: updated.UTC().Format(time.RFC3339),
	})
}
