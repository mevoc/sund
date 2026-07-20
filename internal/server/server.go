// Package server hosts the Sund HTTP API. At this stage it exposes only a
// health endpoint; the two-plane API (management + transport) lands on top of
// this skeleton. See docs/Sund-ImplementationGuide.md (API sketch).
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

// Config holds server construction options.
type Config struct {
	Version string
}

// Server is the Sund HTTP server.
type Server struct {
	cfg     Config
	handler http.Handler
}

// New builds a Server with its routes registered. Routing uses the stdlib
// method-and-pattern mux (Go 1.22+); no third-party router — see PRD, the
// one-binary bar.
func New(cfg Config) *Server {
	s := &Server{cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
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
