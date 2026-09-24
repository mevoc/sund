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
	"crypto/tls"
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
	tlsDir := fs.String("tls-dir", envOr("SUND_TLS_DIR", defaultTLSDir),
		"directory holding the pinned CA and leaf; created on first run (env: SUND_TLS_DIR)")
	plainHTTP := fs.Bool("http", envOr("SUND_HTTP", "") != "",
		"serve plain HTTP instead of pinned TLS — for WebPKI mode behind a TLS-terminating proxy (env: SUND_HTTP)")
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

	// Pinned TLS is the default (PRD, Server address: "pinned mode remains the
	// self-host-first default"). tlsid.Load creates the CA and leaf on first run,
	// so this needs no setup — which is what made the old HTTP default only a
	// convenience. Plain HTTP stays available for WebPKI mode, where a
	// TLS-terminating proxy holds a publicly trusted certificate, but it is now
	// an explicit choice rather than what you get by not choosing.
	if *plainHTTP {
		log.Printf("sund %s listening on %s (plain http, db=%s)", version, *addr, *dbPath)
		log.Printf("no transport security of its own: expect a TLS-terminating proxy in front (WebPKI mode)")
		return srv.Run(ctx, *addr)
	}

	id, err := tlsid.Load(*tlsDir)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}
	log.Printf("sund %s listening on %s (https, pinned, db=%s)", version, *addr, *dbPath)
	log.Printf("pinned address: sund://<host>%s#%s", portSuffix(*addr), id.Fingerprint)
	return srv.RunTLS(ctx, *addr, id.ServerTLSConfig())
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
	case len(args) >= 2 && args[0] == "device" && args[1] == "promote":
		return runAdminDevicePromote(args[2:])
	}
	return fmt.Errorf("usage:\n" +
		"  sund admin account create [--db sund.db] [--quota standard] [--admin-mode flat] [--ttl 15m] [--json]\n" +
		"  sund admin device quota <device-id> [<bytes>] [--db sund.db]\n" +
		"  sund admin device promote <device-id> [--db sund.db]")
}

// runAdminDevicePromote makes a device an admin. It is the operator's way back
// into a managed account whose only admin left — the invariant stops an account
// losing its last admin to an act on ANOTHER device, but a device may always
// revoke itself, so the bad state stays reachable by design (PRD, decision 12).
func runAdminDevicePromote(args []string) error {
	fs := flag.NewFlagSet("admin device promote", flag.ExitOnError)
	dbPath := fs.String("db", envOr("SUND_DB", "sund.db"), "path to the SQLite database file (env: SUND_DB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: sund admin device promote <device-id> [--db sund.db]")
	}
	deviceID := fs.Arg(0)

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
	if err := st.PromoteDevice(ctx, deviceID); err != nil {
		return fmt.Errorf("promote: %w", err)
	}

	// A role change is an administrative act. This one has no acting device, so
	// it pings every device in the account rather than all-but-the-actor: the
	// host is the one party none of this binds, so it must not hold the only
	// silent act.
	pingAccount(ctx, st, dev.AccountID, "")
	fmt.Printf("%s: promoted to admin\n", deviceID)
	return nil
}

// pingAccount wakes every device in an account except exceptID (empty for an
// operator act, which has no actor to exclude).
func pingAccount(ctx context.Context, st *store.Store, accountID, exceptID string) {
	devs, err := st.ListDevices(ctx, accountID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not list devices to ping: %v\n", err)
		return
	}
	pinger := push.NewUnifiedPush(&http.Client{Timeout: 10 * time.Second})
	for _, d := range devs {
		if d.ID == exceptID || d.Revoked || d.PushEndpoint == "" {
			continue
		}
		if err := pinger.Ping(ctx, d.PushEndpoint, push.Normal); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not ping %s: %v\n", d.ID, err)
		}
	}
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
	adminMode := fs.String("admin-mode", store.AdminModeFlat,
		"administration mode: flat (every device an admin) or managed (admin-only revoke/invite); fixed at provisioning")
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
	acc, err := st.CreateAccount(ctx, *quota, *quotaBytes, *adminMode)
	if err != nil {
		return fmt.Errorf("create account: %w", err)
	}
	// The first device of an account is an admin whatever the mode, so the
	// founding invitation grants admin explicitly.
	token, _, err := st.CreateInvitation(ctx, acc.ID, *ttl, store.RoleAdmin)
	if err != nil {
		return fmt.Errorf("create invitation: %w", err)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{
			"account_id":       acc.ID,
			"invitation_token": token,
		})
	}
	fmt.Printf("account:    %s  (administration: %s)\n", acc.ID, acc.AdminMode)
	fmt.Printf("invitation: %s  (single-use, expires in %s)\n", token, *ttl)
	return nil
}

// runHealth probes the server's /health endpoint and exits non-zero if it is not
// OK. It exists so a distroless container (no shell, no curl) can still declare a
// Docker HEALTHCHECK: ["CMD", "/sund", "health"].
func runHealth(args []string) error {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	addr := fs.String("addr", envOr("SUND_ADDR", ":5870"), "server address to probe (env: SUND_ADDR)")
	plainHTTP := fs.Bool("http", envOr("SUND_HTTP", "") != "",
		"probe over plain HTTP instead of TLS (env: SUND_HTTP)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return checkHealth(healthURL(*addr, *plainHTTP))
}

// healthURL turns a listen address into a probe URL, filling in a loopback host
// for the bare ":port" form the server listens on.
// defaultTLSDir is where `serve` keeps the pinned CA and leaf when nothing else
// is given. Relative, like the default database path, so the whole deployment is
// one directory the operator can copy (the Holm bar).
const defaultTLSDir = "tls"

func healthURL(addr string, plainHTTP bool) string {
	host := addr
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	if plainHTTP {
		return "http://" + host + "/health"
	}
	return "https://" + host + "/health"
}

func checkHealth(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// The probe is a liveness check on the server's own address, usually loopback
	// inside a container, so it does not verify the certificate: it is asking
	// "are you up", not "are you who you claim". Pinning is the client's job and
	// happens against the fingerprint in the server address, not here.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // liveness probe, not a trust decision
	}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: status %d", resp.StatusCode)
	}
	return nil
}
