package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrQueueNotFound is returned when a recipient or sender id does not resolve to
// a live queue.
var ErrQueueNotFound = errors.New("queue not found")

// ErrQuotaExceeded is returned when storing a message would push the owning
// account's stored payloads past its quota.
var ErrQuotaExceeded = errors.New("account storage quota exceeded")

// Queue is a unidirectional blind channel. SenderKey is nil until bound.
type Queue struct {
	RecipientID  string
	SenderID     string
	OwnerDevice  string
	RecipientKey ed25519.PublicKey
	SenderKey    ed25519.PublicKey
	Created      time.Time
	Retired      bool
	// QuotaBytes caps the stored payloads held in this queue; 0 means no ceiling.
	// The owner sets it with this queue's recipient key (PRD 0.10, decision 17).
	QuotaBytes int64
}

// Message is one stored ciphertext envelope awaiting delivery.
type Message struct {
	ID         string
	QueueID    string
	Payload    []byte
	ReceivedAt time.Time
	Expires    time.Time
}

// CreateQueue creates an open queue owned by ownerDevice. recipientKey
// authenticates the owner's recv/ack/retire calls; the sender key is bound
// later, on the first SEND.
func (s *Store) CreateQueue(ctx context.Context, ownerDevice string, recipientKey ed25519.PublicKey) (*Queue, error) {
	if len(recipientKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("recipient key: got %d bytes, want %d", len(recipientKey), ed25519.PublicKeySize)
	}
	recipientID, err := newID("rcp_")
	if err != nil {
		return nil, err
	}
	senderID, err := newID("snd_")
	if err != nil {
		return nil, err
	}
	created := nowStr()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO queues (recipient_id, sender_id, owner_device, recipient_key, sender_key, created, retired)
		 VALUES (?, ?, ?, ?, NULL, ?, 0)`,
		recipientID, senderID, ownerDevice, []byte(recipientKey), created,
	); err != nil {
		return nil, err
	}
	t, _ := time.Parse(time.RFC3339, created)
	return &Queue{
		RecipientID:  recipientID,
		SenderID:     senderID,
		OwnerDevice:  ownerDevice,
		RecipientKey: recipientKey,
		Created:      t,
	}, nil
}

const queueColumns = `SELECT recipient_id, sender_id, owner_device, recipient_key, sender_key, created, retired, quota_bytes FROM queues`

// GetQueueByRecipient looks up a queue by its recipient (owner) id.
func (s *Store) GetQueueByRecipient(ctx context.Context, recipientID string) (*Queue, error) {
	return scanQueue(s.db.QueryRowContext(ctx, queueColumns+` WHERE recipient_id=?`, recipientID))
}

// GetQueueBySender looks up a queue by its sender id.
func (s *Store) GetQueueBySender(ctx context.Context, senderID string) (*Queue, error) {
	return scanQueue(s.db.QueryRowContext(ctx, queueColumns+` WHERE sender_id=?`, senderID))
}

// BindSenderKey binds key as the queue's sender key iff it is still unbound and
// the queue is live. It reports whether the binding took effect; a false with no
// error means the queue was already bound (or retired), which the caller treats
// as a rejected rebind.
func (s *Store) BindSenderKey(ctx context.Context, senderID string, key ed25519.PublicKey) (bool, error) {
	if len(key) != ed25519.PublicKeySize {
		return false, fmt.Errorf("sender key: got %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE queues SET sender_key=? WHERE sender_id=? AND sender_key IS NULL AND retired=0`,
		[]byte(key), senderID,
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

// RetireQueue marks a queue retired and drops its undelivered messages in one
// transaction. The row is kept so its ids stay reserved.
func (s *Store) RetireQueue(ctx context.Context, recipientID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE queue_id=?`, recipientID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE queues SET retired=1 WHERE recipient_id=?`, recipientID); err != nil {
		return err
	}
	return tx.Commit()
}

// AppendMessage stores a ciphertext payload on the queue, expiring after ttl.
// It enforces the owning account's storage quota atomically: the check and
// insert share a transaction, so a full account cannot be pushed over its cap.
// Quota counts only non-expired messages, so space frees as messages expire or
// are acked. Returns ErrQuotaExceeded when the cap would be exceeded.
func (s *Store) AppendMessage(ctx context.Context, recipientID string, payload []byte, ttl time.Duration) (*Message, error) {
	id, err := newID("msg_")
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := now.Add(ttl)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Resolve all three storage ceilings in one pass: the queue's own, its owner
	// device's, and the owner's account (PRD 0.10, Accounts). 0 means no ceiling
	// at that level, so a deployment that sets none behaves as it always did.
	var (
		accountID                             string
		queueQuota, deviceQuota, accountQuota int64
		ownerDevice                           string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT d.account_id, q.owner_device, q.quota_bytes, d.quota_bytes, a.quota_bytes
		   FROM queues q
		   JOIN devices d ON q.owner_device = d.id
		   JOIN accounts a ON d.account_id = a.id
		  WHERE q.recipient_id = ?`,
		recipientID,
	).Scan(&accountID, &ownerDevice, &queueQuota, &deviceQuota, &accountQuota)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrQueueNotFound
	}
	if err != nil {
		return nil, err
	}

	nowS := now.Format(time.RFC3339)
	size := int64(len(payload))

	// Narrowest first: the queue level needs no joins at all, so a send refused
	// there costs the least to refuse. Every level uses the same rule — expired
	// rows excluded, and landing exactly on a ceiling succeeds.
	if queueQuota > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM messages
			  WHERE queue_id = ? AND expires > ?`,
			recipientID, nowS,
		).Scan(&used); err != nil {
			return nil, err
		}
		if used+size > queueQuota {
			return nil, ErrQuotaExceeded
		}
	}
	if deviceQuota > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(LENGTH(m.payload)), 0)
			   FROM messages m
			   JOIN queues q ON m.queue_id = q.recipient_id
			  WHERE q.owner_device = ? AND m.expires > ?`,
			ownerDevice, nowS,
		).Scan(&used); err != nil {
			return nil, err
		}
		if used+size > deviceQuota {
			return nil, ErrQuotaExceeded
		}
	}
	if accountQuota > 0 {
		var used int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(LENGTH(m.payload)), 0)
			   FROM messages m
			   JOIN queues q ON m.queue_id = q.recipient_id
			   JOIN devices d ON q.owner_device = d.id
			  WHERE d.account_id = ? AND m.expires > ?`,
			accountID, nowS,
		).Scan(&used); err != nil {
			return nil, err
		}
		if used+size > accountQuota {
			return nil, ErrQuotaExceeded
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO messages (id, queue_id, payload, received_at, expires)
		 VALUES (?, ?, ?, ?, ?)`,
		id, recipientID, payload, now.Format(time.RFC3339), expires.Format(time.RFC3339),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Message{
		ID: id, QueueID: recipientID, Payload: payload,
		ReceivedAt: now.Truncate(time.Second), Expires: expires.Truncate(time.Second),
	}, nil
}

// DrainMessages purges expired messages, then returns the live ones in arrival
// order. Expired messages are deleted unread (PRD, Messages).
func (s *Store) DrainMessages(ctx context.Context, recipientID string) ([]Message, error) {
	now := nowStr()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM messages WHERE queue_id=? AND expires<=?`, recipientID, now); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, queue_id, payload, received_at, expires FROM messages WHERE queue_id=? ORDER BY seq`,
		recipientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Message
	for rows.Next() {
		var (
			m                  Message
			receivedAt, expire string
		)
		if err := rows.Scan(&m.ID, &m.QueueID, &m.Payload, &receivedAt, &expire); err != nil {
			return nil, err
		}
		m.ReceivedAt, _ = time.Parse(time.RFC3339, receivedAt)
		m.Expires, _ = time.Parse(time.RFC3339, expire)
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteMessages removes the named messages from a queue, returning the count
// deleted. Scoping by queue_id ensures a recipient can only delete its own.
func (s *Store) DeleteMessages(ctx context.Context, recipientID string, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, 0, len(ids)+1)
	args = append(args, recipientID)
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM messages WHERE queue_id=? AND id IN (`+placeholders+`)`, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func scanQueue(sc rowScanner) (*Queue, error) {
	var (
		q       Queue
		rkey    []byte
		skey    []byte
		created string
		retired int
	)
	if err := sc.Scan(&q.RecipientID, &q.SenderID, &q.OwnerDevice, &rkey, &skey, &created, &retired, &q.QuotaBytes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrQueueNotFound
		}
		return nil, err
	}
	q.RecipientKey = ed25519.PublicKey(rkey)
	if skey != nil {
		q.SenderKey = ed25519.PublicKey(skey)
	}
	q.Created, _ = time.Parse(time.RFC3339, created)
	q.Retired = retired != 0
	return &q, nil
}
