package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seedAccountAndToken(t *testing.T, st *Store, ttl time.Duration) (accountID, token string) {
	t.Helper()
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err = st.CreateInvitation(ctx, acc.ID, ttl)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	return acc.ID, token
}

func randKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

func TestRegisterDeviceHappyPath(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	accountID, token := seedAccountAndToken(t, st, 15*time.Minute)
	pub := randKey(t)

	dev, err := st.RegisterDevice(ctx, token, pub, "https://ntfy.example/abc", "beacon")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if dev.AccountID != accountID {
		t.Errorf("device account = %q, want %q", dev.AccountID, accountID)
	}
	if !dev.PublicKey.Equal(pub) {
		t.Error("stored public key does not match")
	}

	got, err := st.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.PushEndpoint != "https://ntfy.example/abc" {
		t.Errorf("push endpoint = %q", got.PushEndpoint)
	}
}

func TestRegisterDeviceSingleUse(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_, token := seedAccountAndToken(t, st, 15*time.Minute)

	if _, err := st.RegisterDevice(ctx, token, randKey(t), "", ""); err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	_, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("second RegisterDevice err = %v, want ErrInvalidInvitation", err)
	}
}

func TestRegisterDeviceExpiredToken(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_, token := seedAccountAndToken(t, st, -1*time.Minute) // already expired

	_, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("expired RegisterDevice err = %v, want ErrInvalidInvitation", err)
	}
}

func TestRegisterDeviceUnknownToken(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_, err := st.RegisterDevice(ctx, "not-a-real-token", randKey(t), "", "")
	if !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("unknown token err = %v, want ErrInvalidInvitation", err)
	}
}

func TestListDevices(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	for i := 0; i < 3; i++ {
		token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		if _, err := st.RegisterDevice(ctx, token, randKey(t), "", ""); err != nil {
			t.Fatalf("RegisterDevice: %v", err)
		}
	}

	devs, err := st.ListDevices(ctx, acc.ID)
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 3 {
		t.Fatalf("ListDevices returned %d devices, want 3", len(devs))
	}
}

func TestGetDeviceNotFound(t *testing.T) {
	st := newStore(t)
	_, err := st.GetDevice(context.Background(), "dev_nope")
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("GetDevice err = %v, want ErrDeviceNotFound", err)
	}
}

func TestRevokeDevice(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()

	acc, err := st.CreateAccount(ctx, "standard")
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	dev, err := st.RegisterDevice(ctx, token, randKey(t), "https://push/x", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	q, err := st.CreateQueue(ctx, dev.ID, randKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("ct"), time.Hour); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	if err := st.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	got, err := st.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !got.Revoked {
		t.Error("device should be revoked")
	}
	if got.PushEndpoint != "" {
		t.Errorf("push endpoint = %q, want cleared", got.PushEndpoint)
	}

	gotQ, err := st.GetQueueByRecipient(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("GetQueueByRecipient: %v", err)
	}
	if !gotQ.Retired {
		t.Error("owned queue should be retired")
	}
	msgs, _ := st.DrainMessages(ctx, q.RecipientID)
	if len(msgs) != 0 {
		t.Errorf("owned queue still has %d messages, want 0", len(msgs))
	}
}

func TestRevokeDeviceIdempotent(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	_, token := seedAccountAndToken(t, st, 15*time.Minute)
	dev, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if err := st.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := st.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatalf("second revoke should be a no-op, got: %v", err)
	}
}

func TestCrossAccountIsolation(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()

	_, tokenA := seedAccountAndToken(t, st, 15*time.Minute)
	accB, tokenB := seedAccountAndToken(t, st, 15*time.Minute)

	if _, err := st.RegisterDevice(ctx, tokenA, randKey(t), "", ""); err != nil {
		t.Fatalf("register A: %v", err)
	}
	if _, err := st.RegisterDevice(ctx, tokenB, randKey(t), "", ""); err != nil {
		t.Fatalf("register B: %v", err)
	}

	devsB, err := st.ListDevices(ctx, accB)
	if err != nil {
		t.Fatalf("ListDevices(B): %v", err)
	}
	if len(devsB) != 1 {
		t.Fatalf("account B sees %d devices, want only its own 1", len(devsB))
	}
}
