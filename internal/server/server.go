// Package server hosts the Sund HTTP API. It exposes the health endpoint plus
// the first management-plane routes: unsigned device registration (bootstrap by
// one-time token) and signed device listing. The transport plane (queues,
// send/recv) lands on top of this skeleton. See docs/Sund-ImplementationGuide.md
// (API sketch).
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/mevoc/sund/internal/push"
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
	// Pinger delivers wake-up pings. If nil, pings are dropped (push.NoopPinger).
	Pinger push.Pinger
}

// Server is the Sund HTTP server.
type Server struct {
	cfg       Config
	store     *store.Store
	pinger    push.Pinger
	handler   http.Handler
	nonces    *nonceCache
	clockSkew time.Duration
}

// New builds a Server with its routes registered. Routing uses the stdlib
// method-and-pattern mux (Go 1.22+); no third-party router — see PRD, the
// one-binary bar.
func New(cfg Config, st *store.Store) *Server {
	pinger := cfg.Pinger
	if pinger == nil {
		pinger = push.NoopPinger{}
	}
	s := &Server{
		cfg:       cfg,
		store:     st,
		pinger:    pinger,
		nonces:    newNonceCache(),
		clockSkew: defaultClockSkew,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	// Bootstrap: unsigned, authorized by a one-time enrollment token.
	mux.HandleFunc("POST /v1/devices/register", s.handleRegister)
	// Signed management-plane routes.
	mux.Handle("GET /v1/devices", s.requireSignature(http.HandlerFunc(s.handleListDevices)))
	mux.Handle("POST /v1/devices/{id}/revoke", s.requireSignature(http.HandlerFunc(s.handleRevoke)))
	mux.Handle("GET /v1/devices/{id}/bundle", s.requireSignature(http.HandlerFunc(s.handleGetBundle)))
	mux.Handle("PUT /v1/me/bundle", s.requireSignature(http.HandlerFunc(s.handleSetBundle)))
	mux.Handle("POST /v1/invitations", s.requireSignature(http.HandlerFunc(s.handleCreateInvitation)))
	mux.Handle("GET /v1/invitations", s.requireSignature(http.HandlerFunc(s.handleListInvitations)))
	mux.Handle("POST /v1/invitations/{id}/revoke", s.requireSignature(http.HandlerFunc(s.handleRevokeInvitation)))
	mux.Handle("PUT /v1/me/push", s.requireSignature(http.HandlerFunc(s.handleUpdatePush)))
	mux.Handle("GET /v1/me/quota", s.requireSignature(http.HandlerFunc(s.handleGetQuota)))
	// Queue creation is the plane meeting point: signed by device identity so
	// the server records ownership (quota + wake-up).
	mux.Handle("POST /v1/queues", s.requireSignature(http.HandlerFunc(s.handleCreateQueue)))
	// Transport-plane routes: authenticated by per-queue keys, no device id.
	mux.HandleFunc("POST /v1/send/{sender_id}", s.handleSend)
	mux.HandleFunc("GET /v1/recv/{recipient_id}", s.handleRecv)
	mux.HandleFunc("POST /v1/ack/{recipient_id}", s.handleAck)
	mux.HandleFunc("POST /v1/retire/{recipient_id}", s.handleRetire)
	// The one quota level a client may write: its own queue's. Authenticated by
	// the queue's recipient key, so no device identity enters (PRD, decision 17).
	mux.HandleFunc("POST /v1/quota/{recipient_id}", s.handleSetQueueQuota)
	s.handler = mux
	return s
}

// Handler exposes the router so tests can exercise routes without binding a
// socket.
func (s *Server) Handler() http.Handler { return s.handler }

// Run listens on addr (plain HTTP) and serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// RunTLS listens on addr and serves HTTPS with tlsConf until ctx is cancelled.
func (s *Server) RunTLS(ctx context.Context, addr string, tlsConf *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, tls.NewListener(ln, tlsConf))
}

// serve runs the HTTP server over ln until ctx is cancelled, then shuts down
// gracefully.
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
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

// PurgeInterval is how often the background sweeper deletes expired messages.
// A drain already purges the queue it touches, so the sweeper exists only for
// queues nobody visits; hourly is frequent enough for that and cheap enough to
// run on a device with one CPU.
const PurgeInterval = time.Hour

// RunPurgeLoop deletes expired messages until ctx is cancelled. It is a
// goroutine, not a service: no new process, no scheduler, nothing to configure —
// the Holm bar survives it.
func (s *Server) RunPurgeLoop(ctx context.Context) {
	t := time.NewTicker(PurgeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.store.PurgeExpired(ctx)
			if err != nil {
				log.Printf("purge expired: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("purged %d expired messages", n)
			}
		}
	}
}
