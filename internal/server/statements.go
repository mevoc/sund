package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/mevoc/sund/internal/store"
)

// Administrative statements (PRD 0.13, decision 21). Sund stores opaque blobs
// and serves them back in order. It never parses one, for the reason it never
// parses a key bundle: what an administrative act means is the consumer's
// protocol, and staying out of it is what keeps Sund a relay.
//
// The blob is signed and encrypted by the client. Signing is what lets a peer
// tell a real act from one a hostile host invented; encryption is what stops the
// log from becoming the actor-to-target record the data model refuses. Sund
// cannot check either, which is why neither is a server-side rule — the same
// arrangement bundles have.

type appendStatementRequest struct {
	Statement string `json:"statement"` // base64, opaque to the server
}

type statementView struct {
	Seq       int64  `json:"seq"`
	Statement string `json:"statement"` // base64, as written
	Created   string `json:"created"`
}

// handleAppendStatement writes one statement to the caller's account log.
// Admin-only, which in a flat account is every device: the acts a statement
// describes are admin-only, so the log that vouches for them is too, and it
// keeps a member from filling the account's bounded log.
func (s *Server) handleAppendStatement(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if err := store.RequireAdmin(dev); err != nil {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	var req appendStatementRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	blob, err := base64.StdEncoding.DecodeString(req.Statement)
	if err != nil || len(blob) == 0 {
		writeError(w, http.StatusBadRequest, "invalid statement")
		return
	}

	st, err := s.store.AppendStatement(r.Context(), dev.AccountID, blob)
	if errors.Is(err, store.ErrStatementTooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "statement too large")
		return
	}
	if err != nil {
		log.Printf("append statement: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Writing a statement is not itself an administrative act — the act it
	// describes already pinged the account — so this does not ping again. A
	// client refetches the log on the ping it already gets.
	writeJSON(w, http.StatusCreated, statementView{
		Seq:       st.Seq,
		Statement: base64.StdEncoding.EncodeToString(st.Blob),
		Created:   st.Created.UTC().Format(time.RFC3339),
	})
}

// handleListStatements returns the caller's account log from {since} onward,
// exclusive. Readable by every device in the account, not only admins: the point
// of the log is that peers can check an act for themselves.
//
// since is a path segment rather than a query parameter because the signing
// string covers method and path only — a query filter would be the single
// unsigned input in an otherwise signed API, and a tampered one would silently
// hide entries from a reader.
func (s *Server) handleListStatements(w http.ResponseWriter, r *http.Request) {
	dev, ok := deviceFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	since, err := strconv.ParseInt(r.PathValue("since"), 10, 64)
	if err != nil || since < 0 {
		writeError(w, http.StatusBadRequest, "invalid since")
		return
	}

	sts, err := s.store.ListStatements(r.Context(), dev.AccountID, since)
	if err != nil {
		log.Printf("list statements: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	views := make([]statementView, len(sts))
	for i, st := range sts {
		views[i] = statementView{
			Seq:       st.Seq,
			Statement: base64.StdEncoding.EncodeToString(st.Blob),
			Created:   st.Created.UTC().Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"statements": views})
}
