package client

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mevoc/sund/internal/server"
	"github.com/mevoc/sund/internal/store"
	"github.com/mevoc/sund/internal/tlsid"
)

// newServer runs the real server in-process against a temp database and
// returns a Conn to it plus a factory for fresh accounts' invitation tokens.
func newServer(t *testing.T) (*Conn, func() string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "sund.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(server.New(server.Config{Version: "test"}, st).Handler())
	t.Cleanup(srv.Close)
	token := func() string {
		acc, err := st.CreateAccount(context.Background(), "standard", 0, store.AdminModeFlat)
		if err != nil {
			t.Fatalf("CreateAccount: %v", err)
		}
		tok, _, err := st.CreateInvitation(context.Background(), acc.ID, time.Minute, store.RoleAdmin)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		return tok
	}
	return NewConn(srv.URL, srv.Client()), token
}

func mustKey(t *testing.T) (pub, priv []byte) {
	t.Helper()
	p, k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}

func TestHealth(t *testing.T) {
	conn, _ := newServer(t)
	v, err := conn.Health(context.Background())
	if err != nil || v != "test" {
		t.Fatalf("Health = %q, %v", v, err)
	}
}

func TestManagementPlane(t *testing.T) {
	ctx := context.Background()
	conn, newToken := newServer(t)

	_, k1 := mustKey(t)
	d1, err := Register(ctx, conn, newToken(), k1, "", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if d1.ID == "" || d1.AccountID == "" {
		t.Fatalf("Register returned %+v", d1)
	}

	// A bad token is a 401 APIError, not a transport error.
	_, k2 := mustKey(t)
	_, err = Register(ctx, conn, "not-a-token", k2, "", "")
	if StatusCode(err) != http.StatusUnauthorized {
		t.Fatalf("bad token: got %v, want 401", err)
	}

	// Invite a second device into the account.
	inv, err := d1.CreateInvitation(ctx)
	if err != nil || inv.Token == "" || inv.ID == "" || inv.Expires.IsZero() {
		t.Fatalf("CreateInvitation: %+v %v", inv, err)
	}
	list, err := d1.ListInvitations(ctx)
	if err != nil || len(list) != 1 || list[0].ID != inv.ID || list[0].Token != "" {
		t.Fatalf("ListInvitations: %+v %v", list, err)
	}
	d2, err := Register(ctx, conn, inv.Token, k2, "https://push.example/UP", "")
	if err != nil {
		t.Fatalf("Register second device: %v", err)
	}
	if d2.AccountID != d1.AccountID {
		t.Fatalf("second device landed in account %s, want %s", d2.AccountID, d1.AccountID)
	}

	// Resume from a stored identity and see both devices.
	resumed := NewDevice(conn, d2.ID, k2)
	devs, err := resumed.ListDevices(ctx)
	if err != nil || len(devs) != 2 {
		t.Fatalf("ListDevices: %+v %v", devs, err)
	}
	for _, d := range devs {
		if d.ID == d2.ID && (d.PushEndpoint != "https://push.example/UP" || !d.PublicKey.Equal(d2.PublicKey())) {
			t.Fatalf("device row %+v does not match registration", d)
		}
	}

	// Push endpoint, bundles.
	if err := d1.SetPushEndpoint(ctx, "https://push.example/d1"); err != nil {
		t.Fatalf("SetPushEndpoint: %v", err)
	}
	if err := d1.PublishBundle(ctx, []byte("opaque-bundle")); err != nil {
		t.Fatalf("PublishBundle: %v", err)
	}
	blob, err := d2.GetBundle(ctx, d1.ID)
	if err != nil || string(blob) != "opaque-bundle" {
		t.Fatalf("GetBundle: %q %v", blob, err)
	}

	// Revocation: the revoked device's signed calls fail with 401.
	if err := d1.RevokeDevice(ctx, d2.ID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, err := d2.ListDevices(ctx); StatusCode(err) != http.StatusUnauthorized {
		t.Fatalf("revoked device: got %v, want 401", err)
	}
	devs, _ = d1.ListDevices(ctx)
	var revoked bool
	for _, d := range devs {
		if d.ID == d2.ID {
			revoked = d.Revoked
		}
	}
	if !revoked {
		t.Fatal("revoked device not flagged in the list")
	}
}

func TestTransportPlane(t *testing.T) {
	ctx := context.Background()
	conn, newToken := newServer(t)
	_, dk := mustKey(t)
	owner, err := Register(ctx, conn, newToken(), dk, "", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	rpub, rpriv := mustKey(t)
	ids, err := owner.CreateQueue(ctx, rpub)
	if err != nil || ids.RecipientID == "" || ids.SenderID == "" {
		t.Fatalf("CreateQueue: %+v %v", ids, err)
	}
	recipient := NewRecipient(conn, ids.RecipientID, rpriv)

	_, spriv := mustKey(t)
	sender := NewSender(conn, ids.SenderID, spriv)

	// First send binds the sender key; the second must still verify because the
	// key header is presented on every send.
	id1, err := sender.Send(ctx, []byte("ciphertext-1"), SendOptions{TTL: time.Hour})
	if err != nil || id1 == "" {
		t.Fatalf("Send 1: %q %v", id1, err)
	}
	id2, err := sender.Send(ctx, []byte("ciphertext-2"), SendOptions{Priority: true})
	if err != nil || id2 == "" {
		t.Fatalf("Send 2: %q %v", id2, err)
	}

	// A different key on the same sender id is rejected after binding.
	_, otherKey := mustKey(t)
	if _, err := NewSender(conn, ids.SenderID, otherKey).Send(ctx, []byte("x"), SendOptions{}); StatusCode(err) != http.StatusUnauthorized {
		t.Fatalf("rebind attempt: got %v, want 401", err)
	}

	msgs, err := recipient.Recv(ctx)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("Recv: %+v %v", msgs, err)
	}
	if string(msgs[0].Payload) != "ciphertext-1" || string(msgs[1].Payload) != "ciphertext-2" {
		t.Fatalf("payloads out of order or altered: %q %q", msgs[0].Payload, msgs[1].Payload)
	}
	if msgs[0].ID != id1 || msgs[0].Expires.Before(msgs[0].ReceivedAt) {
		t.Fatalf("message metadata: %+v", msgs[0])
	}

	// Unacked messages are redelivered; acked ones are gone.
	again, _ := recipient.Recv(ctx)
	if len(again) != 2 {
		t.Fatalf("redelivery before ack: %d messages", len(again))
	}
	n, err := recipient.Ack(ctx, []string{id1, id2})
	if err != nil || n != 2 {
		t.Fatalf("Ack: %d %v", n, err)
	}
	if empty, _ := recipient.Recv(ctx); len(empty) != 0 {
		t.Fatalf("after ack: %d messages", len(empty))
	}

	// Retire fails the sender closed.
	if err := recipient.Retire(ctx); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := sender.Send(ctx, []byte("late"), SendOptions{}); StatusCode(err) != http.StatusNotFound {
		t.Fatalf("send to retired queue: got %v, want 404", err)
	}
}

// pinnedServer serves the real /health handler over pinned TLS and returns the
// address a client would be handed.
func pinnedServer(t *testing.T) (Address, *tlsid.Identity) {
	t.Helper()
	id, err := tlsid.Load(t.TempDir())
	if err != nil {
		t.Fatalf("tlsid.Load: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "sund.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewUnstartedServer(server.New(server.Config{Version: "tls"}, st).Handler())
	srv.TLS = id.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return Address{Mode: Pinned, Host: u.Hostname(), Port: port, Fingerprint: id.Fingerprint}, id
}

func TestPinnedModeAcceptsMatchingServer(t *testing.T) {
	addr, _ := pinnedServer(t)
	v, err := Connect(addr).Health(context.Background())
	if err != nil || v != "tls" {
		t.Fatalf("pinned Health = %q, %v", v, err)
	}
}

func TestPinnedModeRejectsMismatchAsIdentityError(t *testing.T) {
	addr, _ := pinnedServer(t)
	other, err := tlsid.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	addr.Fingerprint = other.Fingerprint
	_, err = Connect(addr).Health(context.Background())
	if !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("mismatched pin: got %v, want ErrServerIdentity", err)
	}
}

func TestWebPKIModeRejectsUntrustedCertAsIdentityError(t *testing.T) {
	// httptest's self-signed certificate is exactly what WebPKI mode must
	// refuse: not trusted by the platform store.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	addr := Address{Mode: WebPKI, Host: "localhost", Port: port}
	_, err := Connect(addr).Health(context.Background())
	if !errors.Is(err, ErrServerIdentity) {
		t.Fatalf("untrusted cert: got %v, want ErrServerIdentity", err)
	}
}

func TestPinnedClientNeverSkipsVerification(t *testing.T) {
	// The transport built for a pinned address must carry a verify callback;
	// InsecureSkipVerify alone would be a silent downgrade.
	addr, _ := pinnedServer(t)
	tr := Connect(addr).HTTP.Transport.(*http.Transport)
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("pinned transport has no peer verification callback")
	}
	if tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("pinned transport allows TLS < 1.2")
	}
}

// newManagedServer is newServer with managed accounts, so the role model is
// live: devices enrol as members unless their invitation grants admin.
func newManagedServer(t *testing.T) (*Conn, func() string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "sund.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(server.New(server.Config{Version: "test"}, st).Handler())
	t.Cleanup(srv.Close)
	token := func() string {
		acc, err := st.CreateAccount(context.Background(), "standard", 0, store.AdminModeManaged)
		if err != nil {
			t.Fatalf("CreateAccount: %v", err)
		}
		tok, _, err := st.CreateInvitation(context.Background(), acc.ID, time.Minute, store.RoleAdmin)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		return tok
	}
	return NewConn(srv.URL, srv.Client()), token
}

// The client can drive a managed account end to end: mint a member invitation,
// see the roles in the device list, promote, and be refused where the server
// refuses. Postiljon is this package's first consumer and the PRD recommends a
// managed account for exactly that two-component stack, so a client that cannot
// do this leaves the recommendation unusable.
func TestManagedAccountThroughTheClient(t *testing.T) {
	ctx := context.Background()
	conn, newToken := newManagedServer(t)

	_, adminKey := mustKey(t)
	admin, err := Register(ctx, conn, newToken(), adminKey, "", "")
	if err != nil {
		t.Fatalf("register admin: %v", err)
	}

	inv, err := admin.CreateInvitationAs(ctx, RoleMember)
	if err != nil {
		t.Fatalf("CreateInvitationAs: %v", err)
	}
	_, memberKey := mustKey(t)
	member, err := Register(ctx, conn, inv.Token, memberKey, "", "")
	if err != nil {
		t.Fatalf("register member: %v", err)
	}

	roles := map[string]string{}
	devs, err := admin.ListDevices(ctx)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range devs {
		roles[d.ID] = d.Role
	}
	if roles[admin.ID] != RoleAdmin || roles[member.ID] != RoleMember {
		t.Fatalf("roles = %v, want the first device admin and the invited one member", roles)
	}

	// A member is refused the admin-only acts, through the client.
	if err := member.RevokeDevice(ctx, admin.ID); err == nil {
		t.Fatal("a member must not be able to revoke a peer")
	}
	if _, err := member.CreateInvitation(ctx); err == nil {
		t.Fatal("a member must not be able to mint an invitation")
	}

	// The admin promotes it, and now it can.
	if err := admin.SetRole(ctx, member.ID, RoleAdmin); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	if _, err := member.CreateInvitation(ctx); err != nil {
		t.Fatalf("a promoted device should be able to mint: %v", err)
	}
}

// A device reads its own ceiling and usage, and sets its own queue's ceiling.
// Those are the two quota calls a client may make; the account and device
// ceilings are the operator's, because they cap someone else.
func TestQuotaThroughTheClient(t *testing.T) {
	ctx := context.Background()
	conn, newToken := newServer(t)

	_, dk := mustKey(t)
	dev, err := Register(ctx, conn, newToken(), dk, "", "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rpub, rpriv := mustKey(t)
	ids, err := dev.CreateQueue(ctx, rpub)
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	recipient := NewRecipient(conn, ids.RecipientID, rpriv)

	if err := recipient.SetQuota(ctx, 128); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}

	// Sending past the queue's ceiling is refused, while the device and account
	// ceilings are untouched.
	_, spriv := mustKey(t)
	sender := NewSender(conn, ids.SenderID, spriv)
	if _, err := sender.Send(ctx, make([]byte, 100), SendOptions{}); err != nil {
		t.Fatalf("first send should fit: %v", err)
	}
	if _, err := sender.Send(ctx, make([]byte, 100), SendOptions{}); err == nil {
		t.Fatal("the queue ceiling should have refused the second send")
	}

	q, err := dev.Quota(ctx)
	if err != nil {
		t.Fatalf("Quota: %v", err)
	}
	if q.QuotaBytes != 0 {
		t.Errorf("device ceiling = %d, want 0 (none set)", q.QuotaBytes)
	}
	if q.StoredBytes != 100 {
		t.Errorf("stored bytes = %d, want 100", q.StoredBytes)
	}
}

// Statements round-trip as opaque bytes and read back in order.
func TestStatementsThroughTheClient(t *testing.T) {
	ctx := context.Background()
	conn, newToken := newServer(t)

	_, dk := mustKey(t)
	dev, err := Register(ctx, conn, newToken(), dk, "", "")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	first, err := dev.AppendStatement(ctx, []byte("opaque-one"))
	if err != nil {
		t.Fatalf("AppendStatement: %v", err)
	}
	if first.Seq != 1 {
		t.Fatalf("first statement seq = %d, want 1", first.Seq)
	}
	if _, err := dev.AppendStatement(ctx, []byte("opaque-two")); err != nil {
		t.Fatalf("AppendStatement: %v", err)
	}

	all, err := dev.Statements(ctx, 0)
	if err != nil {
		t.Fatalf("Statements: %v", err)
	}
	if len(all) != 2 || string(all[0].Blob) != "opaque-one" || string(all[1].Blob) != "opaque-two" {
		t.Fatalf("log = %v, want the two blobs in order", all)
	}

	// Polling from the highest seq held returns nothing new.
	rest, err := dev.Statements(ctx, all[len(all)-1].Seq)
	if err != nil {
		t.Fatalf("Statements(since): %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("since=latest returned %d statements, want none", len(rest))
	}
}
