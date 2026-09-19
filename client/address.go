package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mevoc/sund/internal/tlsid"
)

// Mode is a transport-trust mode of the pinning contract. It is part of the
// stored server identity: a change of mode is a re-pairing event (§8.5).
type Mode int

const (
	// Pinned — sund://host:port#fingerprint. Sund terminates TLS itself; the
	// client trusts only the offline CA whose SPKI SHA-256 is the fingerprint.
	Pinned Mode = iota + 1
	// WebPKI — sund+webpki://host[:port]. Sund sits behind a reverse proxy with
	// a publicly trusted certificate; the platform's default verification applies.
	WebPKI
)

func (m Mode) String() string {
	switch m {
	case Pinned:
		return "pinned"
	case WebPKI:
		return "webpki"
	}
	return "unknown"
}

// Address is a parsed server address. Store the whole value durably: the mode
// and fingerprint are the identity, the host and port are only where to
// connect (§1, §8.1).
type Address struct {
	Mode        Mode
	Host        string
	Port        int
	Fingerprint string // pinned mode only; 64 lowercase hex chars
}

// ParseAddress parses a server address and rejects, rather than reinterprets,
// anything malformed: a sund:// address without a well-formed fragment, a
// sund+webpki:// address with one, and an IP-literal host under WebPKI. Mode
// is stated by the scheme, never inferred (§8.1).
func ParseAddress(s string) (Address, error) {
	u, err := url.Parse(s)
	if err != nil {
		return Address{}, fmt.Errorf("sund: malformed address: %w", err)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Opaque != "" {
		return Address{}, errors.New("sund: malformed address: only scheme, host, port and fragment are allowed")
	}
	host := u.Hostname()
	if host == "" {
		return Address{}, errors.New("sund: malformed address: missing host")
	}

	switch u.Scheme {
	case "sund":
		if u.Port() == "" {
			return Address{}, errors.New("sund: malformed sund:// address: port is required")
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return Address{}, errors.New("sund: malformed sund:// address: bad port")
		}
		if !validFingerprint(u.Fragment) {
			return Address{}, errors.New("sund: malformed sund:// address: fragment must be 64 lowercase hex characters")
		}
		return Address{Mode: Pinned, Host: host, Port: port, Fingerprint: u.Fragment}, nil

	case "sund+webpki":
		if u.Fragment != "" || strings.Contains(s, "#") {
			return Address{}, errors.New("sund: malformed sund+webpki:// address: no fragment allowed")
		}
		if net.ParseIP(host) != nil {
			return Address{}, errors.New("sund: malformed sund+webpki:// address: host must be a DNS name")
		}
		port := 443
		if u.Port() != "" {
			port, err = strconv.Atoi(u.Port())
			if err != nil || port < 1 || port > 65535 {
				return Address{}, errors.New("sund: malformed sund+webpki:// address: bad port")
			}
		}
		return Address{Mode: WebPKI, Host: host, Port: port}, nil
	}
	return Address{}, fmt.Errorf("sund: unknown address scheme %q", u.Scheme)
}

func validFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// String renders the address back in its canonical form.
func (a Address) String() string {
	switch a.Mode {
	case Pinned:
		return fmt.Sprintf("sund://%s#%s", net.JoinHostPort(a.Host, strconv.Itoa(a.Port)), a.Fingerprint)
	case WebPKI:
		if a.Port == 443 {
			return "sund+webpki://" + a.Host
		}
		return "sund+webpki://" + net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
	}
	return ""
}

// BaseURL is the https:// origin requests are sent to. Both modes are TLS;
// the contract forbids plain HTTP (§8.3).
func (a Address) BaseURL() string {
	return "https://" + net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

// httpClient builds the HTTP client for the address's mode. Pinned mode
// replaces default verification with the fingerprint check (internal/tlsid,
// the reference implementation of contract §4). WebPKI mode is the platform
// default with nothing changed (§8.2).
func (a Address) httpClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	switch a.Mode {
	case Pinned:
		tr.TLSClientConfig = tlsid.ClientTLSConfig(a.Fingerprint)
	case WebPKI:
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: a.Host}
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}
