package push

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type received struct {
	method   string
	body     []byte
	priority string
}

func TestUnifiedPushSendsEmptyBody(t *testing.T) {
	ch := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- received{method: r.Method, body: b, priority: r.Header.Get("Priority")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	up := NewUnifiedPush(srv.Client())
	if err := up.Ping(context.Background(), srv.URL, High); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	got := <-ch
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if len(got.body) != 0 {
		t.Errorf("ping body = %q, want empty", got.body)
	}
	if got.priority != "high" {
		t.Errorf("Priority header = %q, want high", got.priority)
	}
}

func TestUnifiedPushNormalHasNoPriority(t *testing.T) {
	ch := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ch <- received{priority: r.Header.Get("Priority")}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	up := NewUnifiedPush(srv.Client())
	if err := up.Ping(context.Background(), srv.URL, Normal); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got := <-ch; got.priority != "" {
		t.Errorf("Priority header = %q, want none", got.priority)
	}
}

func TestUnifiedPushReportsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	up := NewUnifiedPush(srv.Client())
	if err := up.Ping(context.Background(), srv.URL, Normal); err == nil {
		t.Fatal("Ping to a failing endpoint should return an error")
	}
}

func TestNoopPinger(t *testing.T) {
	if err := (NoopPinger{}).Ping(context.Background(), "anything", High); err != nil {
		t.Fatalf("NoopPinger.Ping: %v", err)
	}
}
