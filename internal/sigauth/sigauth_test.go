package sigauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSigningStringNilEqualsEmpty(t *testing.T) {
	a := SigningString("GET", "/v1/devices", "ts", "nonce", nil)
	b := SigningString("GET", "/v1/devices", "ts", "nonce", []byte(""))
	if string(a) != string(b) {
		t.Fatalf("nil and empty body must produce identical signing strings")
	}
}

func TestSigningStringFieldsMatter(t *testing.T) {
	base := SigningString("GET", "/v1/devices", "ts", "nonce", nil)
	variants := map[string][]byte{
		"method": SigningString("POST", "/v1/devices", "ts", "nonce", nil),
		"path":   SigningString("GET", "/v1/other", "ts", "nonce", nil),
		"ts":     SigningString("GET", "/v1/devices", "ts2", "nonce", nil),
		"nonce":  SigningString("GET", "/v1/devices", "ts", "nonce2", nil),
		"body":   SigningString("GET", "/v1/devices", "ts", "nonce", []byte("x")),
	}
	for name, v := range variants {
		if string(v) == string(base) {
			t.Errorf("changing %s did not change the signing string", name)
		}
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := SigningString("POST", "/v1/devices/register", "2026-07-20T10:04:12Z", "n1", []byte(`{"x":1}`))
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("valid signature failed to verify")
	}
	if ed25519.Verify(pub, msg, append([]byte{}, sig[:len(sig)-1]...)) {
		t.Fatal("truncated signature verified")
	}
}
