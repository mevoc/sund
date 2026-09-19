package client

import (
	"strings"
	"testing"
)

const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseAddressPinned(t *testing.T) {
	a, err := ParseAddress("sund://relay.example:5870#" + fp)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if a.Mode != Pinned || a.Host != "relay.example" || a.Port != 5870 || a.Fingerprint != fp {
		t.Fatalf("parsed %+v", a)
	}
	if a.BaseURL() != "https://relay.example:5870" {
		t.Fatalf("BaseURL = %s", a.BaseURL())
	}
	if a.String() != "sund://relay.example:5870#"+fp {
		t.Fatalf("String = %s", a.String())
	}
	// IP literals are fine in pinned mode: identity is the key, not the host.
	if _, err := ParseAddress("sund://192.168.1.10:5870#" + fp); err != nil {
		t.Fatalf("IP literal rejected in pinned mode: %v", err)
	}
}

func TestParseAddressWebPKI(t *testing.T) {
	a, err := ParseAddress("sund+webpki://relay.example")
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if a.Mode != WebPKI || a.Host != "relay.example" || a.Port != 443 || a.Fingerprint != "" {
		t.Fatalf("parsed %+v", a)
	}
	if a.String() != "sund+webpki://relay.example" {
		t.Fatalf("String = %s", a.String())
	}
	b, err := ParseAddress("sund+webpki://relay.example:8443")
	if err != nil || b.Port != 8443 || b.String() != "sund+webpki://relay.example:8443" {
		t.Fatalf("port form: %+v %v", b, err)
	}
}

// Contract §1 and §8.1: malformed addresses are rejected outright, never
// reinterpreted as the other mode.
func TestParseAddressRejects(t *testing.T) {
	cases := map[string]string{
		"pinned without fragment":    "sund://relay.example:5870",
		"pinned with empty fragment": "sund://relay.example:5870#",
		"pinned short fragment":      "sund://relay.example:5870#abcd",
		"pinned uppercase fragment":  "sund://relay.example:5870#" + strings.ToUpper(fp),
		"pinned without port":        "sund://relay.example#" + fp,
		"webpki with fragment":       "sund+webpki://relay.example#" + fp,
		"webpki with empty fragment": "sund+webpki://relay.example#",
		"webpki IP literal":          "sund+webpki://192.168.1.10",
		"webpki IPv6 literal":        "sund+webpki://[::1]:443",
		"plain https":                "https://relay.example",
		"unknown scheme":             "sund+plain://relay.example",
		"path":                       "sund://relay.example:5870/v1#" + fp,
		"query":                      "sund://relay.example:5870?x=1#" + fp,
		"userinfo":                   "sund://user@relay.example:5870#" + fp,
		"empty host":                 "sund://:5870#" + fp,
		"bad port":                   "sund://relay.example:99999#" + fp,
	}
	for name, s := range cases {
		if a, err := ParseAddress(s); err == nil {
			t.Errorf("%s: accepted %q as %+v", name, s, a)
		}
	}
}
