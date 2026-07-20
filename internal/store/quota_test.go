package store

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// seedQueueWithQuota creates an account with an explicit byte quota and returns a
// queue owned by a device in it.
func seedQueueWithQuota(t *testing.T, st *Store, quotaBytes int64) *Queue {
	t.Helper()
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "test", quotaBytes)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	dev, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	q, err := st.CreateQueue(ctx, dev.ID, randKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	return q
}

func TestQuotaEnforcedAtCap(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueueWithQuota(t, st, 250) // room for two 100-byte payloads, not three

	payload := bytes.Repeat([]byte("x"), 100)
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("second append: %v", err)
	}
	_, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour)
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("third append err = %v, want ErrQuotaExceeded", err)
	}
}

func TestQuotaFreedAfterDelete(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueueWithQuota(t, st, 150)

	payload := bytes.Repeat([]byte("y"), 100)
	m, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour)
	if err != nil {
		t.Fatalf("first append: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second append err = %v, want ErrQuotaExceeded", err)
	}

	// Acking the first message frees space for another.
	if _, err := st.DeleteMessages(ctx, q.RecipientID, []string{m.ID}); err != nil {
		t.Fatalf("DeleteMessages: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("append after free: %v", err)
	}
}

func TestQuotaExcludesExpiredMessages(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueueWithQuota(t, st, 150)

	payload := bytes.Repeat([]byte("z"), 100)
	// An already-expired message must not occupy quota.
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, -1*time.Minute); err != nil {
		t.Fatalf("append expired: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("append after expired should fit: %v", err)
	}
}

func TestQuotaIsPerAccount(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()

	full := seedQueueWithQuota(t, st, 100)
	other := seedQueueWithQuota(t, st, 100)

	payload := bytes.Repeat([]byte("q"), 100)
	if _, err := st.AppendMessage(ctx, full.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("append to full account: %v", err)
	}
	// The first account is now at its cap; the second is unaffected.
	if _, err := st.AppendMessage(ctx, full.RecipientID, payload, time.Hour); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("second append to full account err = %v, want ErrQuotaExceeded", err)
	}
	if _, err := st.AppendMessage(ctx, other.RecipientID, payload, time.Hour); err != nil {
		t.Fatalf("other account should have its own quota: %v", err)
	}
}

func TestQuotaZeroMeansUnlimited(t *testing.T) {
	// A quota_bytes of 0 (what a pre-quota, migrated account gets) is unlimited,
	// so upgrading a database never retroactively blocks existing accounts.
	st := newStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard", 0)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE accounts SET quota_bytes=0 WHERE id=?`, acc.ID); err != nil {
		t.Fatalf("simulate migrated account: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	dev, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	q, err := st.CreateQueue(ctx, dev.ID, randKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}

	payload := bytes.Repeat([]byte("u"), 1000)
	for i := 0; i < 20; i++ {
		if _, err := st.AppendMessage(ctx, q.RecipientID, payload, time.Hour); err != nil {
			t.Fatalf("append %d under unlimited quota: %v", i, err)
		}
	}
}
