package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
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
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err = st.CreateInvitation(ctx, acc.ID, ttl, RoleAdmin)
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
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	for i := 0; i < 3; i++ {
		token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
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

func TestListInvitationsOutstandingOnly(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	// One live, one expired, one that gets consumed.
	_, live, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation live: %v", err)
	}
	if _, _, err := st.CreateInvitation(ctx, acc.ID, -1*time.Minute, RoleAdmin); err != nil {
		t.Fatalf("CreateInvitation expired: %v", err)
	}
	consumedToken, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation consumed: %v", err)
	}
	if _, err := st.RegisterDevice(ctx, consumedToken, randKey(t), "", ""); err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	invs, err := st.ListInvitations(ctx, acc.ID)
	if err != nil {
		t.Fatalf("ListInvitations: %v", err)
	}
	if len(invs) != 1 || invs[0].ID != live.ID {
		t.Fatalf("outstanding = %+v, want only the live invitation %q", invs, live.ID)
	}
}

func TestRevokeInvitationBlocksRegistration(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, inv, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	revoked, err := st.RevokeInvitation(ctx, acc.ID, inv.ID)
	if err != nil {
		t.Fatalf("RevokeInvitation: %v", err)
	}
	if !revoked {
		t.Fatal("revoke should have taken effect")
	}

	// The revoked token cannot enroll a device.
	if _, err := st.RegisterDevice(ctx, token, randKey(t), "", ""); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatalf("register with revoked token err = %v, want ErrInvalidInvitation", err)
	}
	// It is no longer listed.
	if invs, _ := st.ListInvitations(ctx, acc.ID); len(invs) != 0 {
		t.Fatalf("revoked invitation still listed: %+v", invs)
	}
}

func TestRevokeInvitationIsAccountScoped(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	accA, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount A: %v", err)
	}
	accB, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount B: %v", err)
	}
	_, inv, err := st.CreateInvitation(ctx, accA.ID, 15*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}

	// Account B cannot revoke account A's invitation.
	revoked, err := st.RevokeInvitation(ctx, accB.ID, inv.ID)
	if err != nil {
		t.Fatalf("RevokeInvitation: %v", err)
	}
	if revoked {
		t.Fatal("an invitation must not be revocable from another account")
	}
	if invs, _ := st.ListInvitations(ctx, accA.ID); len(invs) != 1 {
		t.Fatalf("account A's invitation should be untouched, got %+v", invs)
	}
}

func TestRevokeInvitationTwiceIsNoop(t *testing.T) {
	st := newStore(t)
	ctx := context.Background()
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	_, inv, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	if ok, _ := st.RevokeInvitation(ctx, acc.ID, inv.ID); !ok {
		t.Fatal("first revoke should succeed")
	}
	if ok, _ := st.RevokeInvitation(ctx, acc.ID, inv.ID); ok {
		t.Fatal("second revoke should report no change")
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

	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeFlat)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, 15*time.Minute, RoleAdmin)
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

	if err := st.RevokeDevice(ctx, dev.ID, dev.ID); err != nil {
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
	if err := st.RevokeDevice(ctx, dev.ID, dev.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := st.RevokeDevice(ctx, dev.ID, dev.ID); err != nil {
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

// A database written by a pre-0.6 binary still carries messages.status. Opening
// it drops the column, and the drop is idempotent across restarts
// (docs/deviations.md, 2026-09-21 — messages.status is stored but never changes).
func TestMigrateDropsMessagesStatus(t *testing.T) {
	path := t.TempDir() + "/old.db"

	// Reconstruct the old shape: open once, then add the column back as an older
	// binary would have left it.
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := ensureColumn(st.db, "messages", "status", "TEXT NOT NULL DEFAULT 'stored'"); err != nil {
		t.Fatalf("re-add status: %v", err)
	}
	has, err := hasColumn(st.db, "messages", "status")
	if err != nil || !has {
		t.Fatalf("status column not restored for the test: has=%v err=%v", has, err)
	}

	// The drop must carry stored ciphertext across, in order. An empty table
	// would prove only that the ALTER runs.
	ctx := context.Background()
	dev := seedDevice(t, st)
	q, err := st.CreateQueue(ctx, dev.ID, randKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	want := []string{"first", "second", "third"}
	for _, w := range want {
		if _, err := st.AppendMessage(ctx, q.RecipientID, []byte(w), time.Minute); err != nil {
			t.Fatalf("AppendMessage(%q): %v", w, err)
		}
	}
	st.Close()

	// Reopening runs migrate, which must drop it.
	for i := range 2 {
		st, err := Open(path)
		if err != nil {
			t.Fatalf("reopen %d: %v", i, err)
		}
		has, err := hasColumn(st.db, "messages", "status")
		if err != nil {
			t.Fatalf("hasColumn after reopen %d: %v", i, err)
		}
		if has {
			t.Fatalf("reopen %d: messages.status still present", i)
		}

		msgs, err := st.DrainMessages(ctx, q.RecipientID)
		if err != nil {
			t.Fatalf("DrainMessages after reopen %d: %v", i, err)
		}
		if len(msgs) != len(want) {
			t.Fatalf("reopen %d: got %d messages, want %d", i, len(msgs), len(want))
		}
		for j, w := range want {
			if string(msgs[j].Payload) != w {
				t.Fatalf("reopen %d: message %d is %q, want %q (payload or seq order lost in the drop)",
					i, j, msgs[j].Payload, w)
			}
		}
		st.Close()
	}
}

// A message survives the round trip without the dropped column.
func TestAppendDrainAfterStatusDrop(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)

	q, err := st.CreateQueue(ctx, dev.ID, randKey(t))
	if err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := st.AppendMessage(ctx, q.RecipientID, []byte("ciphertext"), time.Minute); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	msgs, err := st.DrainMessages(ctx, q.RecipientID)
	if err != nil {
		t.Fatalf("DrainMessages: %v", err)
	}
	if len(msgs) != 1 || string(msgs[0].Payload) != "ciphertext" {
		t.Fatalf("got %d messages, want 1 with the stored payload", len(msgs))
	}
}

// Two admins revoking each other concurrently must not both succeed. The
// invariant is enforced inside the revocation's transaction for exactly this:
// evaluated outside one it would be merely usually true (PRD, decision 12).
func TestConcurrentRevokeLeavesOneAdmin(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/race.db"
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeManaged)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	mk := func(role string) *Device {
		t.Helper()
		token, _, err := st.CreateInvitation(ctx, acc.ID, time.Minute, role)
		if err != nil {
			t.Fatalf("CreateInvitation: %v", err)
		}
		d, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
		if err != nil {
			t.Fatalf("RegisterDevice: %v", err)
		}
		return d
	}
	a, b := mk(RoleAdmin), mk(RoleAdmin)
	if a.Role != RoleAdmin || b.Role != RoleAdmin {
		t.Fatalf("both devices should be admins, got %q and %q", a.Role, b.Role)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = st.RevokeDevice(ctx, a.ID, b.ID) }()
	go func() { defer wg.Done(); errs[1] = st.RevokeDevice(ctx, b.ID, a.ID) }()
	wg.Wait()

	var admins int
	if err := st.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE account_id=? AND revoked=0 AND role=?`,
		acc.ID, RoleAdmin,
	).Scan(&admins); err != nil {
		t.Fatalf("count: %v", err)
	}
	if admins == 0 {
		t.Fatalf("both revocations landed; the account has no admin left (errs: %v)", errs)
	}
}

// The operator's recovery path exists only where roles do.
func TestPromoteIsRefusedInAFlatAccount(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	dev := seedDevice(t, st)
	if err := st.PromoteDevice(ctx, dev.ID); !errors.Is(err, ErrRoleChangeNotApplicable) {
		t.Fatalf("promote in a flat account: got %v, want ErrRoleChangeNotApplicable", err)
	}
}

// "The last non-revoked admin cannot be demoted" has no self-exception, unlike
// self-revocation. A device that demotes itself is still in the account and can
// then neither invite nor promote, so the account would need operator recovery
// to be usable at all (PRD, Devices → Roles and administration).
func TestSoleAdminCannotDemoteItself(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	acc, err := st.CreateAccount(ctx, "standard", 0, AdminModeManaged)
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	token, _, err := st.CreateInvitation(ctx, acc.ID, time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	only, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	// Alone in the account, and still refused: it would strand itself.
	if err := st.SetDeviceRole(ctx, acc.ID, only.ID, RoleMember); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("sole admin self-demotion: got %v, want ErrLastAdmin", err)
	}
	// Self-revocation, by contrast, is allowed: it empties the account and
	// strands nobody.
	if err := st.RevokeDevice(ctx, only.ID, only.ID); err != nil {
		t.Fatalf("sole admin self-revocation should succeed: %v", err)
	}
}

// Several peers converging on the same removal is normal for a consumer whose
// roster merges tombstones, so all but the first must not see an error.
func TestRevokeByAnotherDeviceStaysIdempotent(t *testing.T) {
	ctx := context.Background()
	st := newStore(t)
	a := seedDevice(t, st)
	token, _, err := st.CreateInvitation(ctx, a.AccountID, time.Minute, RoleAdmin)
	if err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
	b, err := st.RegisterDevice(ctx, token, randKey(t), "", "")
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	if err := st.RevokeDevice(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := st.RevokeDevice(ctx, a.ID, b.ID); err != nil {
		t.Fatalf("second revoke must be a successful no-op, got %v", err)
	}
}
