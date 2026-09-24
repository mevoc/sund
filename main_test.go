package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEnvOr(t *testing.T) {
	const key = "SUND_TEST_ENVOR"
	os.Unsetenv(key)

	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("unset: got %q, want fallback", got)
	}

	t.Setenv(key, "explicit")
	if got := envOr(key, "fallback"); got != "explicit" {
		t.Errorf("set: got %q, want explicit", got)
	}

	t.Setenv(key, "")
	if got := envOr(key, "fallback"); got != "fallback" {
		t.Errorf("empty is treated as unset: got %q, want fallback", got)
	}
}

func TestHealthURL(t *testing.T) {
	cases := map[string]string{
		":5870":          "http://127.0.0.1:5870/health",
		"127.0.0.1:5870": "http://127.0.0.1:5870/health",
		"example:8080":   "http://example:8080/health",
	}
	for addr, want := range cases {
		if got := healthURL(addr, true); got != want {
			t.Errorf("healthURL(%q, http) = %q, want %q", addr, got, want)
		}
	}
	// TLS is the default, so the probe follows it unless asked for HTTP.
	if got := healthURL(":5870", false); got != "https://127.0.0.1:5870/health" {
		t.Errorf("healthURL default = %q, want https", got)
	}
}

func TestCheckHealth(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := checkHealth(ok.URL + "/health"); err != nil {
		t.Errorf("healthy server: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := checkHealth(bad.URL + "/health"); err == nil {
		t.Error("unhealthy server should return an error")
	}

	// Nothing listening → error, not a panic.
	if err := checkHealth("http://127.0.0.1:1/health"); err == nil {
		t.Error("unreachable server should return an error")
	}
}
