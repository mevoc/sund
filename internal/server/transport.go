package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/sigauth"
	"github.com/mevoc/sund/internal/store"
)

// Message policy. Payloads are opaque ciphertext, size-capped; TTLs are clamped
// to a sane range (PRD, Messages). Per-account storage quota is a later slice.
const (
	maxPayloadBytes   = 64 << 10 // 64 KiB
	defaultMessageTTL = 24 * time.Hour
	maxMessageTTL     = 7 * 24 * time.Hour
)

// --- queue creation: the one transport route on the management plane ---

type createQueueRequest struct {
	RecipientKey string `json:"recipient_key"` // base64 Ed25519 public key
}

type createQueueResponse struct {
	RecipientID string `json:"recipient_id"`
	SenderID    string `json:"sender_id"`
}

// handleCreateQueue creates an open queue owned by the calling device. It runs
// behind requireSignature because ownership (quota + wake-up) is the single
// point where the transport plane meets device identity.
func (s *Server) handleCreateQueue(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	var req createQueueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	recipientKey, err := base64.StdEncoding.DecodeString(req.RecipientKey)
	if err != nil || len(recipientKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid recipient_key")
		return
	}

	q, err := s.store.CreateQueue(r.Context(), dev.ID, ed25519.PublicKey(recipientKey))
	if err != nil {
		log.Printf("create queue: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, createQueueResponse{RecipientID: q.RecipientID, SenderID: q.SenderID})
}

// --- transport-plane routes: authenticated by per-queue keys, no device id ---

type sendRequest struct {
	Payload string `json:"payload"` // base64 ciphertext
	TTL     int    `json:"ttl"`     // seconds; <=0 uses the default
}

// handleSend appends a message to a queue addressed by its sender id. On the
// first SEND to an open queue the caller supplies its sender key (Sund-Sender-Key)
// and the server binds it; later SENDs must verify against the bound key and may
// not rebind.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	senderID := r.PathValue("sender_id")
	q, err := s.store.GetQueueBySender(r.Context(), senderID)
	if errors.Is(err, store.ErrQueueNotFound) || (q != nil && q.Retired) {
		writeError(w, http.StatusNotFound, "no such queue")
		return
	}
	if err != nil {
		log.Printf("send lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	env, ok := s.extractSignature(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	key, binding, ok := s.resolveSenderKey(r, q)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !s.verifyAndRecord(r, env, senderID, key) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if binding {
		bound, err := s.store.BindSenderKey(r.Context(), senderID, key)
		if err != nil {
			log.Printf("bind sender key: %v", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !bound {
			// Lost a race to bind, or the queue was retired meanwhile.
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
	}

	var req sendRequest
	if err := json.Unmarshal(env.body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid payload")
		return
	}
	if len(payload) == 0 {
		writeError(w, http.StatusBadRequest, "empty payload")
		return
	}
	if len(payload) > maxPayloadBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}

	msg, err := s.store.AppendMessage(r.Context(), q.RecipientID, payload, clampMessageTTL(req.TTL))
	if err != nil {
		log.Printf("append message: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Wake-up ping (resolve queue -> owner device -> push) lands with the push
	// provider in a later slice; the linkage is q.OwnerDevice.
	writeJSON(w, http.StatusAccepted, map[string]string{"message_id": msg.ID})
}

// resolveSenderKey returns the Ed25519 key to verify a SEND against and whether
// this SEND is the binding one. For an open queue it reads Sund-Sender-Key; for
// a bound queue it uses the stored key and rejects any mismatching header.
func (s *Server) resolveSenderKey(r *http.Request, q *store.Queue) (key ed25519.PublicKey, binding bool, ok bool) {
	header := r.Header.Get(sigauth.HeaderSenderKey)
	if q.SenderKey == nil {
		if header == "" {
			return nil, false, false
		}
		raw, err := base64.StdEncoding.DecodeString(header)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false, false
		}
		return ed25519.PublicKey(raw), true, true
	}
	if header != "" && header != base64.StdEncoding.EncodeToString(q.SenderKey) {
		return nil, false, false
	}
	return q.SenderKey, false, true
}

type messageView struct {
	ID         string `json:"id"`
	Payload    string `json:"payload"` // base64 ciphertext
	ReceivedAt string `json:"received_at"`
	Expires    string `json:"expires"`
}

// handleRecv drains a queue for its owner, authenticated by the recipient key.
func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request) {
	q, _, ok := s.authorizeRecipient(w, r)
	if !ok {
		return
	}
	msgs, err := s.store.DrainMessages(r.Context(), q.RecipientID)
	if err != nil {
		log.Printf("drain: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	views := make([]messageView, len(msgs))
	for i, m := range msgs {
		views[i] = messageView{
			ID:         m.ID,
			Payload:    base64.StdEncoding.EncodeToString(m.Payload),
			ReceivedAt: m.ReceivedAt.UTC().Format(time.RFC3339),
			Expires:    m.Expires.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": views})
}

type ackRequest struct {
	IDs []string `json:"ids"`
}

// handleAck deletes acknowledged messages from a queue.
func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	q, body, ok := s.authorizeRecipient(w, r)
	if !ok {
		return
	}
	var req ackRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	n, err := s.store.DeleteMessages(r.Context(), q.RecipientID, req.IDs)
	if err != nil {
		log.Printf("ack: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": n})
}

// handleRetire retires a queue (rotation), dropping its undelivered messages.
func (s *Server) handleRetire(w http.ResponseWriter, r *http.Request) {
	q, _, ok := s.authorizeRecipient(w, r)
	if !ok {
		return
	}
	if err := s.store.RetireQueue(r.Context(), q.RecipientID); err != nil {
		log.Printf("retire: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"retired": true})
}

// authorizeRecipient looks up the queue named in the recipient_id path segment
// and verifies the request against its recipient key. On any failure it writes
// the response and returns ok=false. On success it also returns the verified
// request body, for handlers (ack) that need it.
func (s *Server) authorizeRecipient(w http.ResponseWriter, r *http.Request) (*store.Queue, []byte, bool) {
	recipientID := r.PathValue("recipient_id")
	q, err := s.store.GetQueueByRecipient(r.Context(), recipientID)
	if errors.Is(err, store.ErrQueueNotFound) || (q != nil && q.Retired) {
		writeError(w, http.StatusNotFound, "no such queue")
		return nil, nil, false
	}
	if err != nil {
		log.Printf("recipient lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, nil, false
	}
	env, ok := s.extractSignature(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	if !s.verifyAndRecord(r, env, recipientID, q.RecipientKey) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil, nil, false
	}
	return q, env.body, true
}

// clampMessageTTL turns a client-supplied seconds value into a bounded duration.
func clampMessageTTL(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultMessageTTL
	}
	d := time.Duration(seconds) * time.Second
	if d > maxMessageTTL {
		return maxMessageTTL
	}
	return d
}
