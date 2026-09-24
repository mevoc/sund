package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func seedDevice(t *testing.T, st *Store) *Device {
	t.Helper()
	ctx := context.Background()
	_, token := seedAccountAndToken(t, st, 15*time.Minute)
	dev, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	return dev
}

func TestSetAndGetBundle(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	dev := seedDevice(t, st)

	blob := []byte("opaque-prekey-bundle-bytes")
	if err := st.SetBundle(ctx, dev.ID, blob); err != nil {
		t.Fatalf("SetBundle: %v", err)
	}

	got, updated, err := st.GetBundle(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("bundle round-trip mismatch: got %q", got)
	}
	if updated.IsZero() {
		t.Error("updated timestamp not set")
	}
}

func TestSetBundleReplaces(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	dev := seedDevice(t, st)

	if err := st.SetBundle(ctx, dev.ID, []byte("first")); err != nil {
		t.Fatalf("SetBundle 1: %v", err)
	}
	if err := st.SetBundle(ctx, dev.ID, []byte("second")); err != nil {
		t.Fatalf("SetBundle 2: %v", err)
	}
	got, _, err := st.GetBundle(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetBundle: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("bundle = %q, want the replacement", got)
	}
}

func TestGetBundleNotFound(t *testing.T) {
	st := newStore(t)
	dev := seedDevice(t, st)
	if _, _, err := st.GetBundle(context.Background(), dev.ID); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("err = %v, want ErrBundleNotFound", err)
	}
}

func TestRevokeClearsBundle(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	dev := seedDevice(t, st)

	if err := st.SetBundle(ctx, dev.ID, []byte("bundle")); err != nil {
		t.Fatalf("SetBundle: %v", err)
	}
	if err := st.RevokeDevice(ctx, dev.ID, dev.ID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if _, _, err := st.GetBundle(ctx, dev.ID); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("revoked device still has a bundle: err = %v", err)
	}
}
