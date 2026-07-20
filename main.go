// Command sund is a blind store-and-forward relay for end-to-end encrypted
// messages between a user's devices. It transports sealed envelopes and never
// interprets them. See docs/Sund-PRD.md for the architecture.
//
// Subcommands:
//
//	sund serve   [--addr :5870] [--db sund.db]
//	sund admin account create [--db sund.db] [--quota standard] [--ttl 15m] [--json]
//	sund version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mevoc/sund/internal/push"
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
	case "admin":
		if err := runAdmin(os.Args[2:]); err != nil {
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
	fmt.Fprintf(os.Stderr, "usage: sund <serve|admin|version> [flags]\n")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":5870", "listen address")
	dbPath := fs.String("db", "sund.db", "path to the SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer st.Close()

	// Shut down cleanly when the test harness (or an operator) sends SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pinger := push.NewUnifiedPush(&http.Client{Timeout: 10 * time.Second})
	srv := server.New(server.Config{Version: version, Pinger: pinger}, st)
	log.Printf("sund %s listening on %s (db=%s)", version, *addr, *dbPath)
	return srv.Run(ctx, *addr)
}

// runAdmin handles the operator surface. Only `account create` exists so far.
func runAdmin(args []string) error {
	if len(args) < 2 || args[0] != "account" || args[1] != "create" {
		return fmt.Errorf("usage: sund admin account create [--db sund.db] [--quota standard] [--ttl 15m] [--json]")
	}

	fs := flag.NewFlagSet("admin account create", flag.ExitOnError)
	dbPath := fs.String("db", "sund.db", "path to the SQLite database file")
	quota := fs.String("quota", "standard", "account quota class")
	quotaBytes := fs.Int64("quota-bytes", 0, "explicit storage quota in bytes (0 = class default)")
	ttl := fs.Duration("ttl", 15*time.Minute, "invitation time-to-live")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer st.Close()

	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, *quota, *quotaBytes)
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, *ttl)
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{
			"account_id":       acc.ID,
			"invitation_token": token,
		})
	}
	fmt.Printf("account:    %s\n", acc.ID)
	fmt.Printf("invitation: %s  (single-use, expires in %s)\n", token, *ttl)
	return nil
}
