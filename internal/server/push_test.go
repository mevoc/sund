package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mevoc/sund/internal/push"
	"github.com/mevoc/sund/internal/store"
)

type pingCall struct {
	endpoint string
	priority push.Priority
}

// fakePinger records pings and streams them on a channel for tests to await.
type fakePinger struct {
	mu    sync.Mutex
	calls []pingCall
	ch    chan pingCall
}

func newFakePinger() *fakePinger {
	return &fakePinger{ch: make(chan pingCall, 16)}
}

func (f *fakePinger) Ping(_ context.Context, endpoint string, priority push.Priority) error {
	c := pingCall{endpoint: endpoint, priority: priority}
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	f.ch <- c
	return nil
}

func (f *fakePinger) await(t *testing.T) pingCall {
	t.Helper()
	select {
	case c := <-f.ch:
		return c
	case <-time.After(2 * time.Second):
		t.Fatal("expected a ping, got none")
		return pingCall{}
	}
}

func (f *fakePinger) awaitNone(t *testing.T) {
	t.Helper()
	select {
	case c := <-f.ch:
		t.Fatalf("expected no ping, got one to %s", c.endpoint)
	case <-time.After(150 * time.Millisecond):
	}
}

func newServerWithPinger(t *testing.T) (*Server, *store.Store, *fakePinger) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	fp := newFakePinger()
	return New(Config{Version: "test", Pinger: fp}, st), st, fp
}

func TestSendPingsQueueOwner(t *testing.T) {
	srv, st, fp := newServerWithPinger(t)
	const endpoint = "https://push.example/owner"

	deviceID, devicePriv := registerDevice(t, srv, st)
	if err := st.UpdatePushEndpoint(context.Background(), deviceID, endpoint); err != nil {
		t.Fatalf("UpdatePushEndpoint: %v", err)
	}
	_, senderID, _ := createQueueForDevice(t, srv, deviceID, devicePriv)

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"payload":%q,"ttl":60}`, base64.StdEncoding.EncodeToString([]byte("ct"))))
	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}

	got := fp.await(t)
	if got.endpoint != endpoint {
		t.Errorf("pinged %q, want %q", got.endpoint, endpoint)
	}
	if got.priority != push.Normal {
		t.Errorf("priority = %v, want Normal", got.priority)
	}
}

func TestSendPriorityPingsHigh(t *testing.T) {
	srv, st, fp := newServerWithPinger(t)
	const endpoint = "https://push.example/sos"

	deviceID, devicePriv := registerDevice(t, srv, st)
	if err := st.UpdatePushEndpoint(context.Background(), deviceID, endpoint); err != nil {
		t.Fatalf("UpdatePushEndpoint: %v", err)
	}
	_, senderID, _ := createQueueForDevice(t, srv, deviceID, devicePriv)

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"payload":%q,"priority":true}`, base64.StdEncoding.EncodeToString([]byte("SOS"))))
	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}

	if got := fp.await(t); got.priority != push.High {
		t.Errorf("priority = %v, want High", got.priority)
	}
}

func TestSendWithoutOwnerEndpointDoesNotPing(t *testing.T) {
	srv, st, fp := newServerWithPinger(t)
	// Owner has no push endpoint registered.
	_, senderID, _ := createQueue(t, srv, st)

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"payload":%q}`, base64.StdEncoding.EncodeToString([]byte("ct"))))
	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202", rec.Code)
	}
	fp.awaitNone(t)
}

func TestRegistrationPingsExistingDevices(t *testing.T) {
	srv, st, fp := newServerWithPinger(t)
	const endpointA = "https://push.example/a"

	// Device A (first in its account) gets a push endpoint.
	aID, aPriv := registerDevice(t, srv, st)
	if err := st.UpdatePushEndpoint(context.Background(), aID, endpointA); err != nil {
		t.Fatalf("UpdatePushEndpoint: %v", err)
	}

	// A invites a second device into the same account.
	invRec := serve(srv, signWith(t, aPriv, aID, http.MethodPost, "/v1/invitations", nil, nil))
	if invRec.Code != http.StatusCreated {
		t.Fatalf("invitation status = %d, want 201", invRec.Code)
	}
	var inv invitationResponse
	if err := json.NewDecoder(invRec.Body).Decode(&inv); err != nil {
		t.Fatalf("decode invitation: %v", err)
	}

	// B registers → A should be pinged for the device-list change.
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	regBody := []byte(fmt.Sprintf(`{"token":%q,"public_key":%q}`, inv.InvitationToken, base64.StdEncoding.EncodeToString(pubB)))
	regRec := serve(srv, httptest.NewRequest(http.MethodPost, "/v1/devices/register", bytes.NewReader(regBody)))
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register B status = %d, want 201", regRec.Code)
	}

	if got := fp.await(t); got.endpoint != endpointA {
		t.Errorf("pinged %q, want %q", got.endpoint, endpointA)
	}
}
