package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestStatementLogIsPerAccountAndBounded(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	a := seedDevice(t, st)
	b := seedDevice(t, st) // a second account

	if a.AccountID == b.AccountID {
		t.Fatal("seedDevice should create separate accounts")
	}

	// Sequence numbers are per account: B's log starts at 1 even though A wrote
	// first, so one account's log says nothing about another's volume.
	for i := range 3 {
		if _, err := st.AppendStatement(ctx, a.AccountID, fmt.Appendf(nil, "a%d", i)); err != nil {
			t.Fatalf("append to A: %v", err)
		}
	}
	first, err := st.AppendStatement(ctx, b.AccountID, []byte("b0"))
	if err != nil {
		t.Fatalf("append to B: %v", err)
	}
	if first.Seq != 1 {
		t.Fatalf("B's first statement has seq %d, want 1 (sequences must be per account)", first.Seq)
	}

	// A reader polls with the highest seq it holds.
	got, err := st.ListStatements(ctx, a.AccountID, 1)
	if err != nil {
		t.Fatalf("ListStatements: %v", err)
	}
	if len(got) != 2 || string(got[0].Blob) != "a1" {
		t.Fatalf("since=1 returned %d statements starting %q, want 2 starting \"a1\"", len(got), got[0].Blob)
	}

	// Cross-account reads return nothing: the log is account-scoped.
	other, err := st.ListStatements(ctx, b.AccountID, 0)
	if err != nil {
		t.Fatalf("ListStatements(B): %v", err)
	}
	if len(other) != 1 {
		t.Fatalf("B sees %d statements, want only its own 1", len(other))
	}
}

func TestStatementLogTrimsOldest(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)

	total := MaxStatementsPerAccount + 5
	for i := range total {
		if _, err := st.AppendStatement(ctx, dev.AccountID, fmt.Appendf(nil, "s%d", i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	all, err := st.ListStatements(ctx, dev.AccountID, 0)
	if err != nil {
		t.Fatalf("ListStatements: %v", err)
	}
	if len(all) != MaxStatementsPerAccount {
		t.Fatalf("log holds %d, want it capped at %d", len(all), MaxStatementsPerAccount)
	}
	// The oldest went, not the newest: a reader must still see recent acts.
	if string(all[len(all)-1].Blob) != fmt.Sprintf("s%d", total-1) {
		t.Fatalf("newest statement is %q, want the last written", all[len(all)-1].Blob)
	}
}

func TestStatementSizeIsCapped(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)

	if _, err := st.AppendStatement(ctx, dev.AccountID, make([]byte, MaxStatementBytes)); err != nil {
		t.Fatalf("a statement exactly at the cap should be accepted: %v", err)
	}
	_, err := st.AppendStatement(ctx, dev.AccountID, make([]byte, MaxStatementBytes+1))
	if !errors.Is(err, ErrStatementTooLarge) {
		t.Fatalf("oversized statement: got %v, want ErrStatementTooLarge", err)
	}
}
