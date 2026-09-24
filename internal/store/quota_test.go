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

// The three ceilings are independent and each refuses on its own, with the
// boundary inclusive: landing exactly on a ceiling succeeds (PRD 0.10,
// decisions 13 and 17).
func TestThreeQuotaLevelsEnforcedIndependently(t *testing.T) {
	ctx := context.Background()

	t.Run("queue ceiling refuses while device and account have room", func(t *testing.T) {
		st := newStore(t)
		dev := seedDevice(t, st)
		q1, err := st.CreateQueue(ctx, dev.ID, randKey(t))
		if err != nil {
			t.Fatalf("CreateQueue: %v", err)
		}
		q2, err := st.CreateQueue(ctx, dev.ID, randKey(t))
		if err != nil {
			t.Fatalf("CreateQueue: %v", err)
		}
		if err := st.SetQueueQuota(ctx, q1.RecipientID, 10); err != nil {
			t.Fatalf("SetQueueQuota: %v", err)
		}

		// Exactly on the ceiling succeeds.
		if _, err := st.AppendMessage(ctx, q1.RecipientID, make([]byte, 10), time.Minute); err != nil {
			t.Fatalf("append at the boundary: %v", err)
		}
		// One more byte does not.
		if _, err := st.AppendMessage(ctx, q1.RecipientID, []byte("x"), time.Minute); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("append past the queue ceiling: got %v, want ErrQuotaExceeded", err)
		}
		// The bulkhead: the owner's other queue is unaffected.
		if _, err := st.AppendMessage(ctx, q2.RecipientID, make([]byte, 1000), time.Minute); err != nil {
			t.Fatalf("sibling queue must still receive: %v", err)
		}
	})

	t.Run("device ceiling spans the queues it owns", func(t *testing.T) {
		st := newStore(t)
		dev := seedDevice(t, st)
		q1, _ := st.CreateQueue(ctx, dev.ID, randKey(t))
		q2, _ := st.CreateQueue(ctx, dev.ID, randKey(t))
		if err := st.SetDeviceQuota(ctx, dev.ID, 100); err != nil {
			t.Fatalf("SetDeviceQuota: %v", err)
		}
		if _, err := st.AppendMessage(ctx, q1.RecipientID, make([]byte, 60), time.Minute); err != nil {
			t.Fatalf("first append: %v", err)
		}
		// The second queue draws on the same device budget.
		if _, err := st.AppendMessage(ctx, q2.RecipientID, make([]byte, 60), time.Minute); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("append past the device ceiling: got %v, want ErrQuotaExceeded", err)
		}
	})

	t.Run("zero at a level means no ceiling there", func(t *testing.T) {
		st := newStore(t)
		dev := seedDevice(t, st)
		q, _ := st.CreateQueue(ctx, dev.ID, randKey(t))
		if err := st.SetQueueQuota(ctx, q.RecipientID, 10); err != nil {
			t.Fatalf("SetQueueQuota: %v", err)
		}
		if _, err := st.AppendMessage(ctx, q.RecipientID, make([]byte, 20), time.Minute); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("want refusal while capped, got %v", err)
		}
		if err := st.SetQueueQuota(ctx, q.RecipientID, 0); err != nil {
			t.Fatalf("clear quota: %v", err)
		}
		if _, err := st.AppendMessage(ctx, q.RecipientID, make([]byte, 20), time.Minute); err != nil {
			t.Fatalf("after clearing the ceiling: %v", err)
		}
	})
}

// Lowering a ceiling below current usage refuses further sends and deletes
// nothing — ceilings are not retroactive (PRD 0.10, Devices → Storage quota).
func TestLoweringAQuotaDiscardsNothing(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)
	q, _ := st.CreateQueue(ctx, dev.ID, randKey(t))

	if _, err := st.AppendMessage(ctx, q.RecipientID, make([]byte, 500), time.Minute); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := st.SetQueueQuota(ctx, q.RecipientID, 10); err != nil {
		t.Fatalf("SetQueueQuota: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("x"), time.Minute); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("further sends must be refused, got %v", err)
	}
	msgs, err := st.DrainMessages(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(msgs) != 1 || len(msgs[0].Payload) != 500 {
		t.Fatalf("the stored message must survive the lowered ceiling, got %d messages", len(msgs))
	}
}

// DeviceStoredBytes is what GET /v1/me/quota reports, so it must exclude
// expired rows exactly as the enforcement check does.
func TestDeviceStoredBytesExcludesExpired(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)
	q, _ := st.CreateQueue(ctx, dev.ID, randKey(t))

	if _, err := st.AppendMessage(ctx, q.RecipientID, make([]byte, 40), time.Minute); err != nil {
		t.Fatalf("live append: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, make([]byte, 40), -time.Minute); err != nil {
		t.Fatalf("expired append: %v", err)
	}
	used, err := st.DeviceStoredBytes(ctx, dev.ID)
	if err != nil {
		t.Fatalf("DeviceStoredBytes: %v", err)
	}
	if used != 40 {
		t.Fatalf("stored bytes = %d, want 40 (expired rows excluded)", used)
	}
}
