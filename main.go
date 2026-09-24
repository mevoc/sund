// Command sund is a blind store-and-forward relay for end-to-end encrypted
// messages between a user's devices. It transports sealed envelopes and never
// interprets them. See docs/Sund-PRD.md for the architecture.
//
// Subcommands:
//
//	sund serve   [--addr :5870] [--db sund.db] [--tls-dir DIR]
//	sund admin account create [--db sund.db] [--quota standard] [--ttl 15m] [--json]
//	sund cert fingerprint [--tls-dir DIR] [--host host:port]
//	sund health  [--addr :5870]
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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mevoc/sund/internal/push"
	"github.com/mevoc/sund/internal/server"
	"github.com/mevoc/sund/internal/store"
	"github.com/mevoc/sund/internal/tlsid"
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
	case "cert":
		if err := runCert(os.Args[2:]); err != nil {
			log.Fatalf("sund: %v", err)
		}
	case "health":
		if err := runHealth(os.Args[2:]); err != nil {
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
	fmt.Fprintf(os.Stderr, "usage: sund <serve|admin|cert|health|version> [flags]\n")
}

// envOr returns the environment variable named key, or def if it is unset or
// empty. It backs the flag defaults so the binary is configurable via the
// environment (12-factor) while an explicit flag still wins.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", envOr("SUND_ADDR", ":5870"), "listen address (env: SUND_ADDR)")
	dbPath := fs.String("db", envOr("SUND_DB", "sund.db"), "path to the SQLite database file (env: SUND_DB)")
	tlsDir := fs.String("tls-dir", envOr("SUND_TLS_DIR", ""),
		"serve HTTPS with fingerprint-pinned certs stored here; empty = plain HTTP (env: SUND_TLS_DIR)")
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

	// Sweep expired messages from queues nobody drains. A drained queue purges
	// itself; this is what keeps "it stores briefly" true for abandoned ones.
	go srv.RunPurgeLoop(ctx)

	if *tlsDir != "" {
		id, err := tlsid.Load(*tlsDir)
		if err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		log.Printf("sund %s listening on %s (https, db=%s)", version, *addr, *dbPath)
		log.Printf("pinned address: sund://<host>%s#%s", portSuffix(*addr), id.Fingerprint)
		return srv.RunTLS(ctx, *addr, id.ServerTLSConfig())
	}

	log.Printf("sund %s listening on %s (http, db=%s)", version, *addr, *dbPath)
	return srv.Run(ctx, *addr)
}

// portSuffix returns the ":port" part of a listen address for the address hint.
func portSuffix(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ""
}

// runCert handles TLS certificate operations. Only `fingerprint` exists so far.
func runCert(args []string) error {
	if len(args) < 1 || args[0] != "fingerprint" {
		return fmt.Errorf("usage: sund cert fingerprint [--tls-dir DIR] [--host host:port]")
	}
	fs := flag.NewFlagSet("cert fingerprint", flag.ExitOnError)
	tlsDir := fs.String("tls-dir", envOr("SUND_TLS_DIR", "certs"), "TLS certificate directory (env: SUND_TLS_DIR)")
	host := fs.String("host", "", "host:port to print a full sund:// address")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	id, err := tlsid.Load(*tlsDir)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	if *host != "" {
		fmt.Printf("sund://%s#%s\n", *host, id.Fingerprint)
	} else {
		fmt.Println(id.Fingerprint)
	}
	return nil
}

// runAdmin handles the operator surface.
func runAdmin(args []string) error {
	switch {
	case len(args) >= 2 && args[0] == "account" && args[1] == "create":
		return runAdminAccountCreate(args[2:])
	case len(args) >= 2 && args[0] == "device" && args[1] == "quota":
		return runAdminDeviceQuota(args[2:])
	}
	return fmt.Errorf("usage:\n" +
		"  sund admin account create [--db sund.db] [--quota standard] [--ttl 15m] [--json]\n" +
		"  sund admin device quota <device-id> [<bytes>] [--db sund.db]")
}

// runAdminDeviceQuota sets or shows a device's storage ceiling. It is the
// operator's write and has no API endpoint, because capping a device silences
// someone else (PRD 0.10, decision 13). Changing it pings the capped device —
// and only that device, since no other can read the result (decision 16) — so
// that a host cannot hold a power over a device silently.
func runAdminDeviceQuota(args []string) error {
	fs := flag.NewFlagSet("admin device quota", flag.ExitOnError)
	dbPath := fs.String("db", envOr("SUND_DB", "sund.db"), "path to the SQLite database file (env: SUND_DB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("usage: sund admin device quota <device-id> [<bytes>] [--db sund.db]")
	}
	deviceID := rest[0]

	st, err := store.Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer st.Close()
	ctx := context.Background()

	dev, err := st.GetDevice(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("device %s: %w", deviceID, err)
	}

	if len(rest) == 1 { // show
		used, err := st.DeviceStoredBytes(ctx, deviceID)
		if err != nil {
			return fmt.Errorf("stored bytes: %w", err)
		}
		if dev.QuotaBytes == 0 {
			fmt.Printf("%s: no ceiling; %d bytes stored\n", deviceID, used)
		} else {
			fmt.Printf("%s: %d bytes ceiling; %d bytes stored\n", deviceID, dev.QuotaBytes, used)
		}
		return nil
	}

	bytes, err := strconv.ParseInt(rest[1], 10, 64)
	if err != nil || bytes < 0 {
		return fmt.Errorf("bytes: want a non-negative integer, got %q", rest[1])
	}
	if err := st.SetDeviceQuota(ctx, deviceID, bytes); err != nil {
		return fmt.Errorf("set quota: %w", err)
	}

	// Tell the device it was capped. Best-effort, like every other ping: if the
	// distributor is unreachable the device learns on its next /v1/me/quota,
	// which clients refetch on any ping (PRD, propagation).
	if dev.PushEndpoint != "" {
		pinger := push.NewUnifiedPush(&http.Client{Timeout: 10 * time.Second})
		if err := pinger.Ping(ctx, dev.PushEndpoint, push.Normal); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not ping %s: %v\n", deviceID, err)
		}
	}
	if bytes == 0 {
		fmt.Printf("%s: ceiling removed\n", deviceID)
	} else {
		fmt.Printf("%s: ceiling set to %d bytes\n", deviceID, bytes)
	}
	return nil
}

func runAdminAccountCreate(args []string) error {

	fs := flag.NewFlagSet("admin account create", flag.ExitOnError)
	dbPath := fs.String("db", envOr("SUND_DB", "sund.db"), "path to the SQLite database file (env: SUND_DB)")
	quota := fs.String("quota", "standard", "account quota class")
	quotaBytes := fs.Int64("quota-bytes", 0, "explicit storage quota in bytes (0 = class default)")
	ttl := fs.Duration("ttl", 15*time.Minute, "invitation time-to-live")
	asJSON := fs.Bool("json", false, "emit machine-readable JSON")
	if err := fs.Parse(args); err != nil {
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

// runHealth probes the server's /health endpoint and exits non-zero if it is not
// OK. It exists so a distroless container (no shell, no curl) can still declare a
// Docker HEALTHCHECK: ["CMD", "/sund", "health"].
func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	addr := fs.String("addr", envOr("SUND_ADDR", ":5870"), "server address to probe (env: SUND_ADDR)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return checkHealth(healthURL(*addr))
}

// healthURL turns a listen address into a probe URL, filling in a loopback host
// for the bare ":port" form the server listens on.
func healthURL(addr string) string {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + "/health"
}

func checkHealth(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
	}
	return nil
}
