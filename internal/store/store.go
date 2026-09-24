// Package store owns the SQLite persistence layer. The driver is
// modernc.org/sqlite (pure Go, no cgo) so the binary builds and links with
// CGO_ENABLED=0 — one static binary, no C toolchain. See PRD decision 10 and
// docs/Sund-ImplementationGuide.md (Toolchain).
//
// The schema is the whole of the server's knowledge (PRD, Data model): accounts,
// invitations and devices land in this slice; bundles, queues and messages
// follow with the endpoints that need them. Timestamps are stored as RFC3339
// UTC text at second precision, which keeps them both human-legible in the file
// and lexicographically ordered for range comparisons.
package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// ErrInvalidInvitation is returned when an enrollment token does not resolve to
// a live, unconsumed, unexpired invitation. It is deliberately undifferentiated
// (not-found vs consumed vs expired) so registration fails closed without
// leaking which case occurred.
var ErrInvalidInvitation = errors.New("invalid, consumed, or expired invitation")

// ErrDeviceNotFound is returned when a device id does not exist.
var ErrDeviceNotFound = errors.New("device not found")

// Store is the SQLite-backed persistence layer.
type Store struct {
	db *sql.DB
}

// Account is a tenant. Quotas attribute to the account (the recipient side the
// server knows); senders stay pseudonymous. QuotaBytes caps the total size of
// stored (undelivered) message payloads across the account's queues; 0 or less
// means unlimited.
type Account struct {
	ID         string
	Created    time.Time
	Quota      string
	Status     string
	QuotaBytes int64
	// AdminMode is "flat" or "managed", fixed at provisioning (PRD decision 12).
	AdminMode string
}

// Administration modes and device roles (PRD, decision 12).
const (
	// AdminModeFlat is the default: every device registers as an admin and may
	// do everything, which is PRD 0.3 behaviour restated.
	AdminModeFlat = "flat"
	// AdminModeManaged restricts revoking another device, minting an invitation
	// and changing a role to devices holding RoleAdmin.
	AdminModeManaged = "managed"

	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Device is one enrolled device. The server stores the public key only.
type Device struct {
	ID           string
	AccountID    string
	PublicKey    ed25519.PublicKey
	PushEndpoint string
	Capabilities string
	Created      time.Time
	LastSeen     time.Time
	Revoked      bool
	// Role is "admin" or "member". Unlike QuotaBytes this IS peer-readable:
	// authority over other devices must be visible to the devices it is held
	// over, which is what makes a managed account non-covert (PRD decision 12).
	Role string
	// QuotaBytes caps the stored payloads in the queues this device owns; 0 means
	// no ceiling at this level. Deliberately absent from the device-list response
	// a peer reads (PRD 0.10, decision 16): a ceiling constrains its own device
	// and confers nothing over anyone, so publishing it would only tell a peer
	// what it costs to silence this one.
	QuotaBytes int64
}

// Open opens (creating if absent) the database at path, applies the schema, and
// verifies connectivity. Pass ":memory:" for an ephemeral in-memory database,
// as the unit suite does.
func Open(path string) (*Store, error) {
	memory := isMemory(path)
	db, err := sql.Open("sqlite", dsn(path, memory))
	if err != nil {
		return nil, err
	}
	// An in-memory database is per-connection, so a pooled second connection
	// would see an empty schema. Pin the pool to one connection for :memory:.
	if memory {
		db.SetMaxOpenConns(1)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping %q: %w", path, err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the underlying database handle.
func (s *Store) Close() error { return s.db.Close() }

func isMemory(path string) bool {
	return path == "" || path == ":memory:" || strings.Contains(path, ":memory:")
}

// dsn builds a modernc DSN carrying per-connection pragmas (foreign keys and a
// busy timeout apply per connection, so they must ride in the DSN, not a
// one-off Exec). WAL is a database-level setting and is meaningless in memory.
func dsn(path string, memory bool) string {
	const pragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if memory {
		return "file::memory:?" + pragmas
	}
	return "file:" + path + "?" + pragmas + "&_pragma=journal_mode(WAL)"
}

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id          TEXT PRIMARY KEY,
  created     TEXT NOT NULL,
  quota       TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  -- 'flat' (every device registers as an admin, PRD 0.3 behaviour) or 'managed'
  -- (devices register with the role their invitation granted). Fixed at
  -- provisioning: there is no endpoint to change it, and that refusal is the
  -- whole specification (PRD, decision 12).
  admin_mode  TEXT NOT NULL DEFAULT 'flat'
);
-- id is a non-secret handle for listing and revoking an invitation; the token
-- itself is never stored (only its hash) or returned after minting. revoked
-- lets an authorized device kill a mis-shared invitation before it is used.
CREATE TABLE IF NOT EXISTS invitations (
  token_hash TEXT PRIMARY KEY,
  id         TEXT NOT NULL DEFAULT '',
  account_id TEXT NOT NULL REFERENCES accounts(id),
  created    TEXT NOT NULL,
  expires    TEXT NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0,
  revoked    INTEGER NOT NULL DEFAULT 0,
  -- The role this token's bearer will hold, so a device never exists in an
  -- account before its role is settled.
  grants_role TEXT NOT NULL DEFAULT 'member'
);
CREATE INDEX IF NOT EXISTS idx_invitations_account ON invitations(account_id);
CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id),
  public_key    BLOB NOT NULL,
  push_endpoint TEXT NOT NULL DEFAULT '',
  capabilities  TEXT NOT NULL DEFAULT '',
  created       TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0,
  quota_bytes   INTEGER NOT NULL DEFAULT 0,
  -- 'admin' or 'member'. Authority over other devices, so unlike quota_bytes it
  -- IS peer-readable: power must be visible to the devices it is held over.
  role          TEXT NOT NULL DEFAULT 'admin'
);
CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

-- A queue is a unidirectional channel owned by one recipient device. The two
-- ids are unrelated random handles: recipient_id reads/acks, sender_id sends.
-- recipient_key is supplied at creation; sender_key is NULL until the first
-- valid SEND binds it (SimpleX "open queue" pattern). owner_device is the sole
-- point where the transport plane meets device identity (quota + wake-up); no
-- column ever links a sender to a queue.
CREATE TABLE IF NOT EXISTS queues (
  recipient_id  TEXT PRIMARY KEY,
  sender_id     TEXT NOT NULL UNIQUE,
  owner_device  TEXT NOT NULL REFERENCES devices(id),
  recipient_key BLOB NOT NULL,
  sender_key    BLOB,
  created       TEXT NOT NULL,
  retired       INTEGER NOT NULL DEFAULT 0,
  quota_bytes   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queues_sender ON queues(sender_id);
CREATE INDEX IF NOT EXISTS idx_queues_owner ON queues(owner_device);

-- seq is a monotonic insertion counter: it gives a queue a stable per-message
-- order independent of the second-precision received_at, so messages sent within
-- the same second still drain in send order (the protocol assumes per-queue
-- ordering). id is the external handle used to ack.
CREATE TABLE IF NOT EXISTS messages (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  id          TEXT NOT NULL UNIQUE,
  queue_id    TEXT NOT NULL REFERENCES queues(recipient_id),
  payload     BLOB NOT NULL,
  received_at TEXT NOT NULL,
  expires     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_queue ON messages(queue_id);

-- A per-device dead-drop of opaque client key material (an X3DH-style prekey
-- bundle) so a device can pair asynchronously with an offline peer. One blob per
-- device; the server stores and serves it verbatim and never interprets it.
CREATE TABLE IF NOT EXISTS bundles (
  device_id TEXT PRIMARY KEY REFERENCES devices(id),
  blob      BLOB NOT NULL,
  updated   TEXT NOT NULL
);
`

func migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	// Columns added after their table's first schema; ensureColumn is a no-op on
	// fresh databases and backfills older ones.
	if err := ensureColumn(db, "accounts", "quota_bytes", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "invitations", "id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "invitations", "revoked", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// Index on invitations.id must come after the column is guaranteed to exist.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_invitations_id ON invitations(id)`); err != nil {
		return err
	}
	// The administration model (PRD, decision 12). Defaults are chosen so an
	// existing database migrates to `flat` with every device an admin, which is
	// exactly the behaviour it had before the columns existed.
	if err := ensureColumn(db, "accounts", "admin_mode", "TEXT NOT NULL DEFAULT 'flat'"); err != nil {
		return err
	}
	if err := ensureColumn(db, "devices", "role", "TEXT NOT NULL DEFAULT 'admin'"); err != nil {
		return err
	}
	if err := ensureColumn(db, "invitations", "grants_role", "TEXT NOT NULL DEFAULT 'member'"); err != nil {
		return err
	}
	// The device and queue quota levels (PRD 0.9, decisions 13 and 17). 0 means no
	// ceiling at that level, so an existing database keeps its behaviour exactly.
	if err := ensureColumn(db, "devices", "quota_bytes", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureColumn(db, "queues", "quota_bytes", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	// messages.status never held anything but 'stored' — an ack deletes the row
	// and an expired message is purged — so it described no behaviour a client
	// could observe (PRD 0.6, docs/deviations.md 2026-09-21). Dropped rather than
	// defined: it never reached the wire, so nothing outside this package saw it.
	return dropColumn(db, "messages", "status")
}

// dropColumn removes column from table if it is still present, so a database
// written by an older binary loses it on startup. The inverse of ensureColumn.
func dropColumn(db *sql.DB, table, column string) error {
	has, err := hasColumn(db, table, column)
	if err != nil || !has {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " DROP COLUMN " + column)
	return err
}

// ensureColumn adds column to table with the given DDL if it is not already
// present, so old database files pick up new columns on startup.
func ensureColumn(db *sql.DB, table, column, ddl string) error {
	has, err := hasColumn(db, table, column)
	if err != nil || has {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl)
	return err
}

// hasColumn reports whether table already has column.
func hasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			cid, notnull, pk int
			name, ctype      string
			dflt             any
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			found = true
		}
	}
	return found, rows.Err()
}

func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

// newID returns prefix followed by 18 hex chars of randomness.
func newID(prefix string) (string, error) {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateAccount inserts a new account. quotaClass is recorded as the account's
// tier label; quotaBytes is the enforced storage ceiling, or 0/less to resolve
// it from the class default.
func (s *Store) CreateAccount(ctx context.Context, quotaClass string, quotaBytes int64, adminMode string) (*Account, error) {
	if quotaBytes <= 0 {
		quotaBytes = QuotaBytesForClass(quotaClass)
	}
	if adminMode == "" {
		adminMode = AdminModeFlat
	}
	if adminMode != AdminModeFlat && adminMode != AdminModeManaged {
		return nil, fmt.Errorf("admin mode: want %q or %q, got %q", AdminModeFlat, AdminModeManaged, adminMode)
	}
	id, err := newID("acc_")
	if err != nil {
		return nil, err
	}
	created := nowStr()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (id, created, quota, status, quota_bytes, admin_mode) VALUES (?, ?, ?, 'active', ?, ?)`,
		id, created, quotaClass, quotaBytes, adminMode,
	); err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339, created)
	return &Account{
		ID: id, Created: t, Quota: quotaClass, Status: "active",
		QuotaBytes: quotaBytes, AdminMode: adminMode,
	}, nil
}

// Invitation is a pending enrollment invitation, identified by a non-secret id.
// The plaintext token is never part of this struct.
type Invitation struct {
	ID        string
	AccountID string
	Created   time.Time
	Expires   time.Time
	// GrantsRole is the role the bearer will hold, settled at mint so a device
	// never exists in an account before its role does.
	GrantsRole string
}

// CreateInvitation mints a single-use enrollment token for accountID, valid for
// ttl. The plaintext token is returned once (to be shown to the operator or
// handed to a pairing device); only its hash is stored. The returned Invitation
// carries the non-secret id (for later listing/revoking) and the expiry.
func (s *Store) CreateInvitation(ctx context.Context, accountID string, ttl time.Duration, grantsRole string) (token string, inv *Invitation, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	id, err := newID("inv_")
	if err != nil {
		return "", nil, err
	}
	if grantsRole == "" {
		grantsRole = RoleMember
	}
	if grantsRole != RoleAdmin && grantsRole != RoleMember {
		return "", nil, fmt.Errorf("role: want %q or %q, got %q", RoleAdmin, RoleMember, grantsRole)
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO invitations (token_hash, id, account_id, created, expires, consumed, revoked, grants_role)
		 VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
		hashToken(token), id, accountID, now.Format(time.RFC3339), expires.Format(time.RFC3339), grantsRole,
	); err != nil {
		return "", nil, err
	}
	return token, &Invitation{
		ID: id, AccountID: accountID, GrantsRole: grantsRole,
		Created: now.Truncate(time.Second), Expires: expires.Truncate(time.Second),
	}, nil
}

// ListInvitations returns an account's outstanding invitations: not consumed,
// not revoked, and not yet expired — the set a client can still act on.
func (s *Store) ListInvitations(ctx context.Context, accountID string) ([]Invitation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, created, expires FROM invitations
		  WHERE account_id=? AND consumed=0 AND revoked=0 AND expires>?
		  ORDER BY created, id`,
		accountID, nowStr(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Invitation
	for rows.Next() {
		var (
			inv              Invitation
			created, expires string
		)
		if err := rows.Scan(&inv.ID, &inv.AccountID, &created, &expires); err != nil {
			return nil, err
		}
		inv.Created, _ = time.Parse(time.RFC3339, created)
		inv.Expires, _ = time.Parse(time.RFC3339, expires)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvitation marks an unconsumed invitation revoked so it can no longer be
// used, scoped to accountID for tenant isolation. It reports whether a live
// invitation was actually revoked (false = unknown id, wrong account, already
// consumed, or already revoked).
func (s *Store) RevokeInvitation(ctx context.Context, accountID, id string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE invitations SET revoked=1 WHERE id=? AND account_id=? AND consumed=0 AND revoked=0`,
		id, accountID,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// RegisterDevice atomically consumes the invitation named by token and enrolls a
// device carrying pub. The conditional UPDATE is the single-use guarantee: only
// the first caller to flip consumed 0→1 (with the invitation unexpired) gets a
// row, so a reused, expired, or unknown token yields ErrInvalidInvitation.
func (s *Store) RegisterDevice(ctx context.Context, token string, pub ed25519.PublicKey, pushEndpoint, capabilities string) (*Device, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key: got %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := nowStr()
	hash := hashToken(token)
	res, err := tx.ExecContext(ctx,
		`UPDATE invitations SET consumed=1 WHERE token_hash=? AND consumed=0 AND revoked=0 AND expires > ?`,
		hash, now,
	)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n != 1 {
		return nil, ErrInvalidInvitation
	}

	var accountID, grantsRole, adminMode string
	if err := tx.QueryRowContext(ctx,
		`SELECT i.account_id, i.grants_role, a.admin_mode
		   FROM invitations i JOIN accounts a ON i.account_id = a.id
		  WHERE i.token_hash=?`, hash,
	).Scan(&accountID, &grantsRole, &adminMode); err != nil {
		return nil, err
	}

	// The account's mode decides which role a newly registered device gets. In a
	// flat account every device is an admin, which is PRD 0.3 behaviour; in a
	// managed one the invitation's grant applies. Either way the first device of
	// an account is an admin, because the last-admin invariant would otherwise be
	// unsatisfiable (PRD, decision 12).
	role := RoleAdmin
	if adminMode == AdminModeManaged {
		role = grantsRole
		var existing int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devices WHERE account_id=? AND revoked=0`, accountID,
		).Scan(&existing); err != nil {
			return nil, err
		}
		if existing == 0 {
			role = RoleAdmin
		}
	}

	id, err := newID("dev_")
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices (id, account_id, public_key, push_endpoint, capabilities, created, last_seen, revoked, role)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		id, accountID, []byte(pub), pushEndpoint, capabilities, now, now, role,
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	t, _ := time.Parse(time.RFC3339, now)
	return &Device{
		ID: id, AccountID: accountID, PublicKey: pub,
		PushEndpoint: pushEndpoint, Capabilities: capabilities,
		Created: t, LastSeen: t, Role: role,
	}, nil
}

// GetDevice returns the device with the given id, or ErrDeviceNotFound.
func (s *Store) GetDevice(ctx context.Context, id string) (*Device, error) {
	return scanDevice(s.db.QueryRowContext(ctx, deviceColumns+` WHERE id=?`, id))
}

// ListDevices returns every device in an account, oldest first.
func (s *Store) ListDevices(ctx context.Context, accountID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, deviceColumns+` WHERE account_id=? ORDER BY created, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// TouchLastSeen records that a device made an authenticated request just now.
func (s *Store) TouchLastSeen(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen=? WHERE id=?`, nowStr(), id)
	return err
}

// UpdatePushEndpoint sets (or clears, if empty) a device's wake-up endpoint.
func (s *Store) UpdatePushEndpoint(ctx context.Context, id, endpoint string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET push_endpoint=? WHERE id=?`, endpoint, id)
	return err
}

// RevokeDevice kills a device in one atomic step: its identity key dies
// (revoked=1), its push endpoint is dropped, and every queue it owns is retired
// with its undelivered messages deleted. Afterward the device's signed requests
// fail and its owned queues are unreachable. Idempotent — revoking an
// already-revoked device is a no-op that still succeeds.
// RevokeDevice revokes a device. callerID is the device that asked; pass the
// target's own id for a self-revocation, which is always permitted — withholding
// it protects nothing, since a device can discard its own key regardless, and it
// is the only remedy a member has against an admin (PRD, decision 12).
//
// The last-admin invariant is enforced here, inside the same transaction as the
// write: an account never loses its last admin to an act performed on ANOTHER
// device. Two admins revoking each other concurrently therefore cannot both
// pass — one becomes the last admin and its revocation is refused.
func (s *Store) RevokeDevice(ctx context.Context, callerID, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if callerID != id {
		var accountID, role string
		if err := tx.QueryRowContext(ctx,
			`SELECT account_id, role FROM devices WHERE id=? AND revoked=0`, id,
		).Scan(&accountID, &role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceNotFound
			}
			return err
		}
		if role == RoleAdmin {
			if err := assertNotLastAdmin(ctx, tx, accountID, id); err != nil {
				return err
			}
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM messages WHERE queue_id IN (SELECT recipient_id FROM queues WHERE owner_device=?)`,
		id,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE queues SET retired=1 WHERE owner_device=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM bundles WHERE device_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET revoked=1, push_endpoint='' WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

const deviceColumns = `SELECT id, account_id, public_key, push_endpoint, capabilities, created, last_seen, revoked, quota_bytes, role FROM devices`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDevice(sc rowScanner) (*Device, error) {
	var (
		d                 Device
		pub               []byte
		created, lastSeen string
		revoked           int
	)
	if err := sc.Scan(&d.ID, &d.AccountID, &pub, &d.PushEndpoint, &d.Capabilities, &created, &lastSeen, &revoked, &d.QuotaBytes, &d.Role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	d.PublicKey = ed25519.PublicKey(pub)
	d.Created, _ = time.Parse(time.RFC3339, created)
	d.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
	d.Revoked = revoked != 0
	return &d, nil
}

// ErrQuotaNotChanged is returned when a quota write names no live row.
var ErrQuotaNotChanged = errors.New("no such device or queue")

// SetDeviceQuota sets a device's storage ceiling, in bytes; 0 removes it. This
// is the operator's write (PRD 0.10, decision 13): capping a device silences
// someone else, so it deliberately has no API endpoint.
func (s *Store) SetDeviceQuota(ctx context.Context, deviceID string, bytes int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE devices SET quota_bytes=? WHERE id=? AND revoked=0`, bytes, deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrQuotaNotChanged
	}
	return nil
}

// DeviceStoredBytes is the live payload total across the queues a device owns:
// accepted, unacked and unexpired. Expired-but-unpurged rows do not count, the
// same rule the enforcement check applies (PRD, Devices → Storage quota).
func (s *Store) DeviceStoredBytes(ctx context.Context, deviceID string) (int64, error) {
	var used int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(LENGTH(m.payload)), 0)
		   FROM messages m
		   JOIN queues q ON m.queue_id = q.recipient_id
		  WHERE q.owner_device = ? AND m.expires > ?`,
		deviceID, nowStr(),
	).Scan(&used)
	return used, err
}

// SetQueueQuota sets a queue's storage ceiling, in bytes; 0 removes it. Unlike
// the other two levels this is the owner's own write, authenticated by the
// queue's recipient key: capping your own inbound channel limits only what you
// receive, so it is nobody's weapon (PRD 0.10, decision 17).
func (s *Store) SetQueueQuota(ctx context.Context, recipientID string, bytes int64) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE queues SET quota_bytes=? WHERE recipient_id=? AND retired=0`, bytes, recipientID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrQuotaNotChanged
	}
	return nil
}

// AccountQuotaBytes returns an account's storage ceiling; 0 means none. It is
// the one account-level figure a device may learn about itself (PRD, decision
// 16): a static constant that binds every device equally and describes none of
// them. Account *usage* is deliberately not exposed — a number every member
// could read would be a coarse activity signal about all of its peers.
func (s *Store) AccountQuotaBytes(ctx context.Context, accountID string) (int64, error) {
	var q int64
	err := s.db.QueryRowContext(ctx, `SELECT quota_bytes FROM accounts WHERE id=?`, accountID).Scan(&q)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDeviceNotFound
	}
	return q, err
}

// ErrNotAdmin is returned when an act reserved to admins is attempted by a
// member in a managed account.
var ErrNotAdmin = errors.New("admin role required")

// ErrLastAdmin is returned when an act would leave an account with no
// non-revoked admin while other devices remain.
var ErrLastAdmin = errors.New("account would lose its last admin")

// ErrRoleChangeNotApplicable is returned by SetDeviceRole in a flat account,
// where every device is an admin by definition of the mode: there is nothing to
// promote, nothing to demote, and no walking a flat account into a managed one
// one demotion at a time (PRD, decision 12).
var ErrRoleChangeNotApplicable = errors.New("roles are not changeable in a flat account")

// RequireAdmin reports whether dev may perform an admin-only act. The rule is
// mode-independent — flat is simply the case where every device is an admin,
// not a second code path.
func RequireAdmin(dev *Device) error {
	if dev.Role != RoleAdmin {
		return ErrNotAdmin
	}
	return nil
}

// SetDeviceRole promotes or demotes a device within its account. Admin-only, and
// refused outright in a flat account. The last-admin invariant is enforced in
// the same transaction as the write: evaluated outside one it would be merely
// usually true, which is the same as false.
func (s *Store) SetDeviceRole(ctx context.Context, accountID, deviceID, role string) error {
	if role != RoleAdmin && role != RoleMember {
		return fmt.Errorf("role: want %q or %q, got %q", RoleAdmin, RoleMember, role)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var mode string
	if err := tx.QueryRowContext(ctx, `SELECT admin_mode FROM accounts WHERE id=?`, accountID).Scan(&mode); err != nil {
		return err
	}
	if mode != AdminModeManaged {
		return ErrRoleChangeNotApplicable
	}

	var current string
	if err := tx.QueryRowContext(ctx,
		`SELECT role FROM devices WHERE id=? AND account_id=? AND revoked=0`, deviceID, accountID,
	).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		return err
	}
	if current == RoleAdmin && role == RoleMember {
		if err := assertNotLastAdmin(ctx, tx, accountID, deviceID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET role=? WHERE id=?`, role, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// assertNotLastAdmin fails if deviceID is the account's only non-revoked admin
// while other non-revoked devices remain. An account whose last device is also
// its last admin is not stranding anyone, so that case is allowed.
func assertNotLastAdmin(ctx context.Context, tx *sql.Tx, accountID, deviceID string) error {
	var otherAdmins, otherDevices int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE account_id=? AND revoked=0 AND role=? AND id<>?`,
		accountID, RoleAdmin, deviceID,
	).Scan(&otherAdmins); err != nil {
		return err
	}
	if otherAdmins > 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devices WHERE account_id=? AND revoked=0 AND id<>?`,
		accountID, deviceID,
	).Scan(&otherDevices); err != nil {
		return err
	}
	if otherDevices > 0 {
		return ErrLastAdmin
	}
	return nil
}

// PromoteDevice is the operator's recovery path for a managed account that lost
// its only admin (PRD, decision 12). Refused against a revoked device and in a
// flat account, where every non-revoked device is already an admin.
func (s *Store) PromoteDevice(ctx context.Context, deviceID string) error {
	var mode string
	if err := s.db.QueryRowContext(ctx,
		`SELECT a.admin_mode FROM devices d JOIN accounts a ON d.account_id=a.id WHERE d.id=? AND d.revoked=0`,
		deviceID,
	).Scan(&mode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceNotFound
		}
		return err
	}
	if mode != AdminModeManaged {
		return ErrRoleChangeNotApplicable
	}
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET role=? WHERE id=?`, RoleAdmin, deviceID)
	return err
}
