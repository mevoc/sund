package tlsid

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// serve starts an HTTPS server with id's config on a random port and returns its
// base URL.
func serve(t *testing.T, id *Identity) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", id.ServerTLSConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return "https://" + ln.Addr().String()
}

func get(url string, clientCfg *tls.Config) error {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientCfg}}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	return nil
}

func TestLoadGeneratesAndPins(t *testing.T) {
	dir := t.TempDir()
	id, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(id.Fingerprint) != 64 { // hex SHA-256
		t.Fatalf("fingerprint = %q, want 64 hex chars", id.Fingerprint)
	}
	for _, f := range []string{"ca.crt", "ca.key", "server.crt", "server.key"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("expected %s to exist: %v", f, err)
		}
	}
}

func TestFingerprintStableAcrossReload(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir)
	if err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprint changed across reload: %s vs %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestLeafRotationKeepsFingerprint(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir)
	if err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	// Rotate the leaf (delete it); the CA and thus the pin must survive.
	os.Remove(filepath.Join(dir, "server.crt"))
	os.Remove(filepath.Join(dir, "server.key"))
	second, err := Load(dir)
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if first.Fingerprint != second.Fingerprint {
		t.Fatalf("leaf rotation changed the pin: %s vs %s", first.Fingerprint, second.Fingerprint)
	}
}

func TestPinnedClientAcceptsMatch(t *testing.T) {
	id, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	url := serve(t, id)
	if err := get(url, ClientTLSConfig(id.Fingerprint)); err != nil {
		t.Fatalf("pinned client should accept the matching server: %v", err)
	}
}

func TestPinnedClientRejectsMismatch(t *testing.T) {
	id, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	url := serve(t, id)

	// A different server's fingerprint must be rejected (MITM detection).
	other, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load other: %v", err)
	}
	if err := get(url, ClientTLSConfig(other.Fingerprint)); err == nil {
		t.Fatal("pinned client accepted a server with the wrong fingerprint")
	}
}

func TestDefaultVerificationRejectsSelfSigned(t *testing.T) {
	id, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	url := serve(t, id)
	// Standard WebPKI verification (no pin) must reject the private CA.
	if err := get(url, &tls.Config{MinVersion: tls.VersionTLS12}); err == nil {
		t.Fatal("default verification unexpectedly accepted the self-signed chain")
	}
}
