package main

import (
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
