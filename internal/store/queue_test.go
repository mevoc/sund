package store

import (
	"context"
	"testing"
	"time"
)

func seedQueue(t *testing.T, st *Store) *Queue {
	t.Helper()
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard")
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

func TestCreateAndGetQueue(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueue(t, st)

	if q.RecipientID == q.SenderID {
		t.Fatal("recipient and sender ids must be unrelated")
	}
	if q.SenderKey != nil {
		t.Fatal("new queue must be open (nil sender key)")
	}

	byR, err := st.GetQueueByRecipient(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("GetQueueByRecipient: %v", err)
	}
	byS, err := st.GetQueueBySender(ctx, q.SenderID)
	if err != nil {
		t.Fatalf("GetQueueBySender: %v", err)
	}
	if byR.RecipientID != byS.RecipientID {
		t.Fatal("both lookups must resolve to the same queue")
	}
}

func TestBindSenderKeyOnce(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueue(t, st)

	bound, err := st.BindSenderKey(ctx, q.SenderID, randKey(t))
	if err != nil {
		t.Fatalf("BindSenderKey: %v", err)
	}
	if !bound {
		t.Fatal("first bind should succeed")
	}
	// A second bind must not take effect (the key is already set).
	bound, err = st.BindSenderKey(ctx, q.SenderID, randKey(t))
	if err != nil {
		t.Fatalf("second BindSenderKey: %v", err)
	}
	if bound {
		t.Fatal("second bind must be rejected")
	}
}

func TestAppendDrainDelete(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueue(t, st)

	m1, err := st.AppendMessage(ctx, q.RecipientID, []byte("ciphertext-1"), time.Hour)
	if err != nil {
		t.Fatalf("AppendMessage 1: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("ciphertext-2"), time.Hour); err != nil {
		t.Fatalf("AppendMessage 2: %v", err)
	}

	msgs, err := st.DrainMessages(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("DrainMessages: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("drained %d messages, want 2", len(msgs))
	}

	n, err := st.DeleteMessages(ctx, q.RecipientID, []string{m1.ID})
	if err != nil {
		t.Fatalf("DeleteMessages: %v", err)
	}
	if n != 1 {
		t.Fatalf("deleted %d, want 1", n)
	}
	msgs, _ = st.DrainMessages(ctx, q.RecipientID)
	if len(msgs) != 1 {
		t.Fatalf("after delete, drained %d, want 1", len(msgs))
	}
}

func TestMessageTTLExpiry(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueue(t, st)

	// A message whose TTL is already in the past must be purged unread.
	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("stale"), -1*time.Minute); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	msgs, err := st.DrainMessages(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("DrainMessages: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("expired message survived: got %d, want 0", len(msgs))
	}
}

func TestRetireDropsMessages(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	q := seedQueue(t, st)

	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("x"), time.Hour); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := st.RetireQueue(ctx, q.RecipientID); err != nil {
		t.Fatalf("RetireQueue: %v", err)
	}

	got, err := st.GetQueueByRecipient(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("GetQueueByRecipient: %v", err)
	}
	if !got.Retired {
		t.Fatal("queue should be retired")
	}
	msgs, _ := st.DrainMessages(ctx, q.RecipientID)
	if len(msgs) != 0 {
		t.Fatalf("retire left %d messages, want 0", len(msgs))
	}
}
