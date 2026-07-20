// Package store owns the SQLite persistence layer. The driver is
// modernc.org/sqlite (pure Go, no cgo) so the binary builds and links with
// CGO_ENABLED=0 — one static binary, no C toolchain. See PRD decision 10 and
// docs/Sund-ImplementationGuide.md (Toolchain).
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Open opens (creating if absent) the SQLite database at path and verifies
// connectivity. Pass ":memory:" for an ephemeral in-memory database, as the
// unit suite does.
//
// The schema (accounts, devices, bundles, invitations, queues, messages) is
// not created here yet; migrations arrive with the endpoints that need them.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping %q: %w", path, err)
	}
	return db, nil
}
