package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	srv := New(Config{Version: "test-1.2.3"})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status field = %q, want %q", body["status"], "ok")
	}
	if body["version"] != "test-1.2.3" {
		t.Errorf("version field = %q, want %q", body["version"], "test-1.2.3")
	}
}

func TestHealthRejectsPost(t *testing.T) {
	srv := New(Config{Version: "x"})

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	// The mux is registered for GET only; other methods must not succeed.
	if rec.Code == http.StatusOK {
		t.Fatalf("POST /health returned 200, want a rejection")
	}
}
