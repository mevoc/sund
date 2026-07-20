// Command sund is a blind store-and-forward relay for end-to-end encrypted
// messages between a user's devices. It transports sealed envelopes and never
// interprets them. See docs/Sund-PRD.md for the architecture.
//
// This is an early scaffold: only `serve` (health endpoint) and `version`
// exist. The two-plane API — management (device identity) and transport
// (pseudonymous queues) — is built on this skeleton.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mevoc/sund/internal/server"
	"github.com/mevoc/sund/internal/store"
)

// version is the build version; override with -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatalf("sund: %v", err)
		}
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: sund <serve|version> [flags]\n")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":5870", "listen address")
	dbPath := fs.String("db", "sund.db", "path to the SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// Shut down cleanly when the test harness (or an operator) sends SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := server.New(server.Config{Version: version})
	log.Printf("sund %s listening on %s (db=%s)", version, *addr, *dbPath)
	return srv.Run(ctx, *addr)
}
