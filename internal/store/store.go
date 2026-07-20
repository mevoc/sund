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
// server knows); senders stay pseudonymous.
type Account struct {
	ID      string
	Created time.Time
	Quota   string
	Status  string
}

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
  id      TEXT PRIMARY KEY,
  created TEXT NOT NULL,
  quota   TEXT NOT NULL,
  status  TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS invitations (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  created    TEXT NOT NULL,
  expires    TEXT NOT NULL,
  consumed   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  account_id    TEXT NOT NULL REFERENCES accounts(id),
  public_key    BLOB NOT NULL,
  push_endpoint TEXT NOT NULL DEFAULT '',
  capabilities  TEXT NOT NULL DEFAULT '',
  created       TEXT NOT NULL,
  last_seen     TEXT NOT NULL,
  revoked       INTEGER NOT NULL DEFAULT 0
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
  retired       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queues_sender ON queues(sender_id);
CREATE INDEX IF NOT EXISTS idx_queues_owner ON queues(owner_device);

CREATE TABLE IF NOT EXISTS messages (
  id          TEXT PRIMARY KEY,
  queue_id    TEXT NOT NULL REFERENCES queues(recipient_id),
  payload     BLOB NOT NULL,
  received_at TEXT NOT NULL,
  expires     TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'stored'
);
CREATE INDEX IF NOT EXISTS idx_messages_queue ON messages(queue_id);
`

func migrate(db *sql.DB) error {
	_, err := db.Exec(schema)
	return err
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

// CreateAccount inserts a new account with the given quota.
func (s *Store) CreateAccount(ctx context.Context, quota string) (*Account, error) {
	id, err := newID("acc_")
	if err != nil {
		return nil, err
	}
	created := nowStr()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (id, created, quota, status) VALUES (?, ?, ?, 'active')`,
		id, created, quota,
	); err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339, created)
	return &Account{ID: id, Created: t, Quota: quota, Status: "active"}, nil
}

// CreateInvitation mints a single-use enrollment token for accountID, valid for
// ttl. The plaintext token is returned once (to be shown to the operator or
// handed to a pairing device); only its hash is stored. The expiry is returned
// so callers can report it.
func (s *Store) CreateInvitation(ctx context.Context, accountID string, ttl time.Duration) (token string, expires time.Time, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now().UTC()
	expires = now.Add(ttl)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO invitations (token_hash, account_id, created, expires, consumed) VALUES (?, ?, ?, ?, 0)`,
		hashToken(token), accountID, now.Format(time.RFC3339), expires.Format(time.RFC3339),
	); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
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
		`UPDATE invitations SET consumed=1 WHERE token_hash=? AND consumed=0 AND expires > ?`,
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

	var accountID string
	if err := tx.QueryRowContext(ctx,
		`SELECT account_id FROM invitations WHERE token_hash=?`, hash,
	).Scan(&accountID); err != nil {
		return nil, err
	}

	id, err := newID("dev_")
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO devices (id, account_id, public_key, push_endpoint, capabilities, created, last_seen, revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		id, accountID, []byte(pub), pushEndpoint, capabilities, now, now,
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
		Created: t, LastSeen: t,
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

const deviceColumns = `SELECT id, account_id, public_key, push_endpoint, capabilities, created, last_seen, revoked FROM devices`

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
	if err := sc.Scan(&d.ID, &d.AccountID, &pub, &d.PushEndpoint, &d.Capabilities, &created, &lastSeen, &revoked); err != nil {
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
