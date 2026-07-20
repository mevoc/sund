package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrBundleNotFound is returned when a device has no published key bundle.
var ErrBundleNotFound = errors.New("bundle not found")

// SetBundle stores (replacing any previous) a device's opaque key bundle. The
// blob is never interpreted — Sund is a dead-drop, not a crypto service, so it
// does not parse the bundle or consume one-time prekeys; managing those is the
// client's concern.
func (s *Store) SetBundle(ctx context.Context, deviceID string, blob []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO bundles (device_id, blob, updated) VALUES (?, ?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET blob=excluded.blob, updated=excluded.updated`,
		deviceID, blob, nowStr(),
	)
	return err
}

// GetBundle returns a device's published key bundle and when it was last set, or
// ErrBundleNotFound. The same bytes are returned to every caller (no popping).
func (s *Store) GetBundle(ctx context.Context, deviceID string) ([]byte, time.Time, error) {
	var (
		blob    []byte
		updated string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT blob, updated FROM bundles WHERE device_id=?`, deviceID,
	).Scan(&blob, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrBundleNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339, updated)
	return blob, t, nil
}
