package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"

	"modernc.org/sqlite"

	smerr "github.com/autarquico/supermgmt/internal/errors"
)

// Snapshot describes a database copy made by SnapshotTo, as read from the
// copy itself so it can never disagree with the bytes that were archived.
type Snapshot struct {
	SchemaVersion int
	// Config is the configuration the daemon had activated when the copy was
	// taken; Generation is 0 when no configuration was ever activated.
	Config ConfigSnapshot
}

// backupSource is the online backup entry point of the SQLite driver.
type backupSource interface {
	NewBackup(dstURI string) (*sqlite.Backup, error)
}

// SnapshotTo copies the whole database into a new file at path with SQLite's
// online backup API (spec §29.1, ADR-0020) and returns what the copy holds.
//
// The copy is one read transaction on a reader connection: writers keep
// committing in WAL mode and the copy sees exactly the state at its start.
// The result is a single self-contained file (rollback journal, no -wal).
func (d *DB) SnapshotTo(ctx context.Context, path string) (Snapshot, error) {
	if err := d.copyTo(ctx, path); err != nil {
		return Snapshot{}, fmt.Errorf("snapshot database: %w", err)
	}
	snap, err := readSnapshot(ctx, path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read database snapshot: %w", err)
	}
	return snap, nil
}

func (d *DB) copyTo(ctx context.Context, path string) error {
	conn, err := d.reader.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Raw(func(driverConn any) error {
		src, ok := driverConn.(backupSource)
		if !ok {
			return errors.New("the sqlite driver offers no online backup")
		}
		backup, err := src.NewBackup(path)
		if err != nil {
			return err
		}
		if _, err := backup.Step(-1); err != nil {
			return errors.Join(err, backup.Finish())
		}
		return backup.Finish()
	})
}

// readSnapshot opens the copy, leaves it in rollback-journal mode and reads
// its schema version and configuration snapshot.
func readSnapshot(ctx context.Context, path string) (snap Snapshot, err error) {
	copyDB, err := sql.Open("sqlite", dsn(path, pragmaQuery(url.Values{}, "journal_mode(DELETE)")))
	if err != nil {
		return Snapshot{}, err
	}
	defer func() { err = errors.Join(err, copyDB.Close()) }()
	copyDB.SetMaxOpenConns(1)

	if err := copyDB.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&snap.SchemaVersion); err != nil {
		return Snapshot{}, fmt.Errorf("schema version: %w", err)
	}
	snap.Config, err = GetConfigSnapshot(ctx, copyDB)
	if smerr.CodeOf(err) == smerr.CodeNotFound {
		return snap, nil
	}
	return snap, err
}
