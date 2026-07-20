// Package server hosts the Sund HTTP API. It exposes the health endpoint plus
// the first management-plane routes: unsigned device registration (bootstrap by
// one-time token) and signed device listing. The transport plane (queues,
// send/recv) lands on top of this skeleton. See docs/Sund-ImplementationGuide.md
// (API sketch).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/store"
)

// maxBodyBytes caps request bodies the server will read. Per-quota payload
// limits arrive with the transport plane; this is a blunt safety bound.
const maxBodyBytes = 1 << 20 // 1 MiB

// defaultClockSkew is the accepted difference between a signed request's
// timestamp and server time.
const defaultClockSkew = 5 * time.Minute

// defaultInvitationTTL is how long a device-minted enrollment token stays valid
// (PRD, Invitations: default 15 minutes, operator-configurable).
const defaultInvitationTTL = 15 * time.Minute

// Config holds server construction options.
type Config struct {
	Version string
}

// Server is the Sund HTTP server.
type Server struct {
	cfg       Config
	store     *store.Store
	handler   http.Handler
	nonces    *nonceCache
	clockSkew time.Duration
}

// New builds a Server with its routes registered. Routing uses the stdlib
// method-and-pattern mux (Go 1.22+); no third-party router — see PRD, the
// one-binary bar.
func New(cfg Config, st *store.Store) *Server {
	s := &Server{
		cfg:       cfg,
		store:     st,
		nonces:    newNonceCache(),
		clockSkew: defaultClockSkew,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	// Bootstrap: unsigned, authorized by a one-time enrollment token.
	mux.HandleFunc("POST /v1/devices/register", s.handleRegister)
	// Signed management-plane routes.
	mux.Handle("GET /v1/devices", s.requireSignature(http.HandlerFunc(s.handleListDevices)))
	mux.Handle("POST /v1/invitations", s.requireSignature(http.HandlerFunc(s.handleCreateInvitation)))
	s.handler = mux
	return s
}

// Handler exposes the router so tests can exercise routes without binding a
// socket.
func (s *Server) Handler() http.Handler { return s.handler }

// Run listens on addr and serves until ctx is cancelled, then shuts down
// gracefully.
func (s *Server) Run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: s.handler}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.cfg.Version,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
