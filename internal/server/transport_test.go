package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mevoc/sund/internal/sigauth"
	"github.com/mevoc/sund/internal/store"
)

// signWith builds a request signed by key. A non-empty deviceID makes it a
// management-plane request (adds the device-id header); otherwise it is a
// transport-plane request keyed by the URL path. extra headers are set last.
func signWith(t *testing.T, key ed25519.PrivateKey, deviceID, method, path string, body []byte, extra map[string]string) *http.Request {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	nonce := randNonce(t)
	sig := ed25519.Sign(key, sigauth.SigningString(method, path, ts, nonce, body))

	var r *http.Request
	if body == nil {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	}
	if deviceID != "" {
		r.Header.Set(sigauth.HeaderDeviceID, deviceID)
	}
	r.Header.Set(sigauth.HeaderTimestamp, ts)
	r.Header.Set(sigauth.HeaderNonce, nonce)
	r.Header.Set(sigauth.HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	return r
}

func serve(srv *Server, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

// createQueue registers a device and creates a queue owned by it.
func createQueue(t *testing.T, srv *Server, st *store.Store) (recipientID, senderID string, recipientPriv ed25519.PrivateKey) {
	t.Helper()
	deviceID, devicePriv := registerDevice(t, srv, st)
	return createQueueForDevice(t, srv, deviceID, devicePriv)
}

// createQueueForDevice creates a queue owned by an already-registered device.
func createQueueForDevice(t *testing.T, srv *Server, deviceID string, devicePriv ed25519.PrivateKey) (recipientID, senderID string, recipientPriv ed25519.PrivateKey) {
	t.Helper()
	recipientPub, recipientPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"recipient_key":%q}`, base64.StdEncoding.EncodeToString(recipientPub)))
	rec := serve(srv, signWith(t, devicePriv, deviceID, http.MethodPost, "/v1/queues", body, nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create queue status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp createQueueResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode queue: %v", err)
	}
	return resp.RecipientID, resp.SenderID, recipientPriv
}

func senderKeyHeader(pub ed25519.PublicKey) map[string]string {
	return map[string]string{sigauth.HeaderSenderKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestQueueSendRecvAck(t *testing.T) {
	srv, st := newTestServer(t)
	recipientID, senderID, recipientPriv := createQueue(t, srv, st)

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	payloadB64 := base64.StdEncoding.EncodeToString([]byte("opaque-ciphertext"))
	sendBody := []byte(fmt.Sprintf(`{"payload":%q,"ttl":60}`, payloadB64))

	// First SEND binds the sender key.
	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, sendBody, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("send status = %d, want 202 (body: %s)", rec.Code, rec.Body.String())
	}

	// Recv drains it.
	rec = serve(srv, signWith(t, recipientPriv, "", http.MethodGet, "/v1/recv/"+recipientID, nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("recv status = %d, want 200", rec.Code)
	}
	var recvResp struct {
		Messages []messageView `json:"messages"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&recvResp); err != nil {
		t.Fatalf("decode recv: %v", err)
	}
	if len(recvResp.Messages) != 1 {
		t.Fatalf("recv returned %d messages, want 1", len(recvResp.Messages))
	}
	if recvResp.Messages[0].Payload != payloadB64 {
		t.Fatalf("payload round-trip mismatch")
	}

	// Ack deletes it.
	ackBody := []byte(fmt.Sprintf(`{"ids":[%q]}`, recvResp.Messages[0].ID))
	rec = serve(srv, signWith(t, recipientPriv, "", http.MethodPost, "/v1/ack/"+recipientID, ackBody, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ack status = %d, want 200", rec.Code)
	}

	// Recv again is empty.
	rec = serve(srv, signWith(t, recipientPriv, "", http.MethodGet, "/v1/recv/"+recipientID, nil, nil))
	var after struct {
		Messages []messageView `json:"messages"`
	}
	json.NewDecoder(rec.Body).Decode(&after)
	if len(after.Messages) != 0 {
		t.Fatalf("after ack, recv returned %d, want 0", len(after.Messages))
	}
}

func TestFirstSendBindsRejectsRebind(t *testing.T) {
	srv, st := newTestServer(t)
	_, senderID, _ := createQueue(t, srv, st)

	body := []byte(fmt.Sprintf(`{"payload":%q}`, base64.StdEncoding.EncodeToString([]byte("m1"))))

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("first send status = %d, want 202", rec.Code)
	}

	// A different key must not be able to hijack the bound queue.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec = serve(srv, signWith(t, otherPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(otherPub)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("rebind send status = %d, want 401", rec.Code)
	}
}

func TestSendUnknownQueue(t *testing.T) {
	srv, _ := newTestServer(t)
	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"payload":%q}`, base64.StdEncoding.EncodeToString([]byte("x"))))

	rec := serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/snd_bogus", body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestRecvWrongKeyRejected(t *testing.T) {
	srv, st := newTestServer(t)
	recipientID, _, _ := createQueue(t, srv, st)

	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := serve(srv, signWith(t, wrongPriv, "", http.MethodGet, "/v1/recv/"+recipientID, nil, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCreateQueueRequiresSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/queues", bytes.NewReader([]byte(`{"recipient_key":"x"}`)))
	rec := serve(srv, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRetireThenSendRejected(t *testing.T) {
	srv, st := newTestServer(t)
	recipientID, senderID, recipientPriv := createQueue(t, srv, st)

	rec := serve(srv, signWith(t, recipientPriv, "", http.MethodPost, "/v1/retire/"+recipientID, nil, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("retire status = %d, want 200", rec.Code)
	}

	senderPub, senderPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte(fmt.Sprintf(`{"payload":%q}`, base64.StdEncoding.EncodeToString([]byte("late"))))
	rec = serve(srv, signWith(t, senderPriv, "", http.MethodPost, "/v1/send/"+senderID, body, senderKeyHeader(senderPub)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("send after retire status = %d, want 404", rec.Code)
	}
}
